using System.ComponentModel.DataAnnotations;

namespace IdentityManager.DTOs
{
    public class UserCreateDto
    {
        public string Email { get; set; }
        public string Password { get; set; }
        public List<string> Roles { get; set; } = new List<string>();
        public string Name { get; internal set; }
    }
}
