using System.Text;
using IdentityManager.Data;
using IdentityManager.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using IdentityManager.Data.Repository;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace IdentityManager
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

            builder.Services.AddControllers();
            builder.Services.AddScoped<IAuthService, AuthService>();
            builder.Services.AddScoped<IUserService, UserService>();
            builder.Services.AddScoped<IRoleService, RoleService>();
            builder.Services.AddScoped<IPasswordService, PasswordService>();
            builder.Services.AddScoped<ITokenRevocationService, TokenRevocationService>();
            builder.Services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
            builder.Services.AddScoped<IClientInfoService, ClientInfoService>();
            builder.Services.AddSingleton<IEmailService, EmailService>();
            builder.Services.AddScoped<IPermissionService, PermissionService>();

            builder.Services.AddIdentity<IdentityUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

            builder.Services.AddHttpContextAccessor();

            var key = builder.Configuration.GetSection("JwtToken:key").Value;

            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero,
                    ValidateLifetime = false,
                    RequireExpirationTime = true,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key))
                };

                options.Events = new JwtBearerEvents
                {
                    OnTokenValidated = async context =>
                    {
                        var userManager = context.HttpContext.RequestServices.GetRequiredService<UserManager<IdentityUser>>();
                        var user = await userManager.GetUserAsync(context.Principal);

                        if (user == null)
                        {
                            context.Fail("User not found");
                            return;
                        }
                        var tokenStamp = context.Principal.FindFirst("AspNet.Identity.SecurityStamp")?.Value;
                        var currentStamp = await userManager.GetSecurityStampAsync(user);

                        if (tokenStamp != currentStamp)
                        {
                            context.Fail("Security stamp mismatch: token revoked");
                        }
                    }
                };
            });


            builder.Services.AddOpenApi();

            var app = builder.Build();

            if (app.Environment.IsDevelopment())
            {
                app.MapOpenApi();
            }

            app.UseHttpsRedirection();

            app.UseAuthorization();

            app.MapControllers();

            using (var scope = app.Services.CreateScope())
            {
                SeedData.Initialize(scope.ServiceProvider);
            }

            app.Run();
        }
    }
}