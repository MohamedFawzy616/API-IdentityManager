namespace IdentityManager.Models
{
    public class RefreshToken
    {
        public int Id { get; set; }
        public string Token { get; set; }
        public string UserId { get; set; }
        public DateTime Expires { get; set; }
        //public bool IsExpired => DateTime.UtcNow >= Expires;
        public DateTime Created { get; set; }
        public string CreatedByIp { get; set; }
        public string? Device { get; set; }
        public string? DeviceId { get; set; }
        public DateTime? RevokedAt { get; set; }
        public string? RevokedByIp { get; set; }
        public string? ReplacedByToken { get; set; }
        public bool IsRevoked { get; set; }
        public bool IsActive { get; set; }
        public string? RevokedReason { get; set; }

        //public bool IsActive => Revoked == null && !IsExpired;
    }
}