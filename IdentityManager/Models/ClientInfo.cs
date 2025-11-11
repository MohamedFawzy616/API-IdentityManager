namespace IdentityManager.Models
{
    public class ClientInfo
    {
        public string IpAddress { get; set; }
        public string DeviceId { get; set; }
        public string UserAgent { get; set; }
        public string Browser { get; set; }
        public string OperatingSystem { get; set; }
        public string DeviceType { get; set; }
        public bool IsMobile { get; set; }
    }
}