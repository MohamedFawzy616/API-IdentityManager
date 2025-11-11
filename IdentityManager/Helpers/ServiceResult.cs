namespace IdentityManager.Helpers
{
    public class ServiceResult<T>
    {
        public bool Success { get; private set; }
        public string Message { get; private set; } = string.Empty;
        public T Data { get; private set; }

        public static ServiceResult<T> Ok(T data, string message = "")
        {
            return new ServiceResult<T>
            {
                Success = true,
                Message = message,
                Data = data
            };
        }

        public static ServiceResult<T> Fail(string message)
        {
            return new ServiceResult<T>
            {
                Success = false,
                Message = message
            };
        }
    }
}