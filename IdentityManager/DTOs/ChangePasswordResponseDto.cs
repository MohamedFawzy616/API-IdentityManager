namespace IdentityManager.DTOs
{
    public class ChangePasswordResponseDto
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public int? RevokedTokensCount { get; set; }
    }
}