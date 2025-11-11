using IdentityManager.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace IdentityManager.Helpers
{
    public class JwtService
    {
        public readonly IConfiguration configuration;
        public JwtService(IConfiguration _configuration)
        {
            configuration = _configuration;
        }


        private async Task<string> GenerateJWTTokenAsync(IdentityUser user)
        {
            var key = configuration.GetSection("JwtToken:key").Value;

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));

            var tokenDecription = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Email,user.Email),
                }),
                Expires = DateTime.UtcNow.AddDays(1),
                SigningCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256Signature)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDecription);
            var jwt = tokenHandler.WriteToken(token);

            return await Task.FromResult(jwt);
        }

        private async Task<RefreshToken> GenerateRefreshTokenAsync(string ipAddress)
        {
            var randomBytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);

            RefreshToken refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(randomBytes),
                Expires = DateTime.UtcNow.AddDays(7),
                Created = DateTime.UtcNow,
                CreatedByIp = ipAddress
            };

            return await Task.FromResult(refreshToken);
        }

    }
}