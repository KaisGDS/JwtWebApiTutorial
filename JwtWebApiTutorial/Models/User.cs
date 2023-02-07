namespace JwtWebApiTutorial.Models
{
    public class User
    {
        public string Username { get; set; } = string.Empty;
        public byte[] PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }
        public string RefreshToken { get; set; } = string.Empty;
        public DateTime TokenCreated { get; set; }
        public DateTime TokenExpire { get; set; }
        public List<string> Roles { get; set; } = new List<string> { "Admin", "User" };
    }
}
