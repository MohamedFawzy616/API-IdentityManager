namespace IdentityManager.DTOs
{
    public class UserReadDto
    {
        public string Id { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
        public string ConfirmEmail { get; set; }


        public string? PhoneNumber { get; set; }
        public bool PhoneNumberConfirmed { get; set; }


        public IList<string> Roles { get; set; } = new List<string>();
        public IList<string> Permissions { get; set; } = new List<string>();


        public DateTime? CreatedAt { get; set; }
        public DateTime? LastLogin { get; set; }

        public bool IsActive { get; set; } = true;
    }
}