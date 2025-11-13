using Serilog;
using System.Text;
using ILogger = Serilog.ILogger;

namespace IdentityManager.Middlewares
{
    public class SerilogRequestLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger _logger;

        public SerilogRequestLoggingMiddleware(RequestDelegate next)
        {
            _next = next;
            _logger = Log.ForContext<SerilogRequestLoggingMiddleware>();
        }

        public async Task InvokeAsync(HttpContext context)
        {
            context.Request.EnableBuffering();

            // 🔹 قراءة محتوى الريكويست
            string requestBody = string.Empty;
            if (context.Request.ContentLength > 0)
            {
                context.Request.Body.Position = 0;
                using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
                requestBody = await reader.ReadToEndAsync();
                context.Request.Body.Position = 0;
            }

            // 🔹 حفظ الـ Response الأصلي مؤقتًا
            var originalBodyStream = context.Response.Body;
            await using var responseBody = new MemoryStream();
            context.Response.Body = responseBody;

            var sw = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                await _next(context);
                sw.Stop();

                context.Response.Body.Seek(0, SeekOrigin.Begin);
                var responseText = await new StreamReader(context.Response.Body).ReadToEndAsync();
                context.Response.Body.Seek(0, SeekOrigin.Begin);

                _logger.Information(
                    "📥 Request {Method} {Path} responded {StatusCode} in {Elapsed:0.0000} ms\nRequestBody: {RequestBody}\nResponseBody: {ResponseBody}",
                    context.Request.Method,
                    context.Request.Path,
                    context.Response.StatusCode,
                    sw.Elapsed.TotalMilliseconds,
                    requestBody,
                    responseText);
            }
            catch (Exception ex)
            {
                _logger.Error(ex,
                    "❌ Exception while processing {Method} {Path}\nRequestBody: {RequestBody}",
                    context.Request.Method,
                    context.Request.Path,
                    requestBody);

                throw;
            }
            finally
            {
                // 🔹 إعادة الـ Response إلى حالته الأصلية
                await responseBody.CopyToAsync(originalBodyStream);
                context.Response.Body = originalBodyStream;
            }
        }
    }

    // 🔹 امتداد لإضافة الميدلوير بسهولة
    public static class SerilogRequestLoggingMiddlewareExtensions
    {
        public static IApplicationBuilder UseSerilogRequestLoggingCustom(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<SerilogRequestLoggingMiddleware>();
        }
    }
}
