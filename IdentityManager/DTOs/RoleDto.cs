namespace IdentityManager.DTOs
{
    public class RoleDto
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public IList<string> Permissions { get; set; } = new List<string>();
    }
}