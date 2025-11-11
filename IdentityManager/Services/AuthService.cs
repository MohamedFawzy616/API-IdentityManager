using IdentityManager.Data.Repository;
using IdentityManager.DTOs;
using IdentityManager.Helpers;
using IdentityManager.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace IdentityManager.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly ITokenRevocationService revocationService;

        private readonly IConfiguration configuration;
        private readonly IHttpContextAccessor httpContextAccessor;
        private readonly IRefreshTokenRepository refreshTokenRepository;
        private readonly IClientInfoService clientInfo;

        public AuthService(IConfiguration _configuration, UserManager<IdentityUser> _userManager, SignInManager<IdentityUser> _signInManager, RoleManager<IdentityRole> _roleManager, ITokenRevocationService _revocationService, IClientInfoService _clientInfo, IRefreshTokenRepository _refreshTokenRepository, IHttpContextAccessor _httpContextAccessor)
        {
            userManager = _userManager;
            roleManager = _roleManager;
            signInManager = _signInManager;
            clientInfo = _clientInfo;
            revocationService = _revocationService;
            configuration = _configuration;
            refreshTokenRepository = _refreshTokenRepository;
            httpContextAccessor = _httpContextAccessor;
        }
 

        public async Task<ServiceResult<UserReadDto>> CreateNewUserAsync(CreateNewUserDto registerDto)
        {
            if (registerDto.Password != registerDto.ConfirmPassword)
            {
                return ServiceResult<UserReadDto>.Fail("Passwords do not match.");
            }

            var user = await userManager.FindByEmailAsync(registerDto.Email);

            if (user != null)
            {
                return ServiceResult<UserReadDto>.Fail("User already exists");
            }

            var newUser = new IdentityUser()
            {
                UserName = registerDto.Name,
                Email = registerDto.Email
            };

            var result = await userManager.CreateAsync(newUser, registerDto.Password);

            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                return ServiceResult<UserReadDto>.Fail(errors);
            }

            if (registerDto.Roles != null && registerDto.Roles.Count > 0)
            {
                foreach (var role in registerDto.Roles)
                {
                    if (!await roleManager.RoleExistsAsync(role))
                    {
                        await roleManager.CreateAsync(new IdentityRole() { Name = role });
                        //return ServiceResult<UserReadDto>.Fail($"Role '{role}' does not exist");
                    }

                    var addRoleResult = await userManager.AddToRoleAsync(newUser, role);
                    if (!addRoleResult.Succeeded)
                    {
                        return ServiceResult<UserReadDto>.Fail($"Failed to assign role '{role}'");
                    }
                }
            }

            UserReadDto userDto = new UserReadDto()
            {
                Id = newUser.Id,
                Email = newUser.Email,
                UserName = newUser.UserName,
                IsActive = true,
                CreatedAt = DateTime.UtcNow,
                Roles = (await userManager.GetRolesAsync(newUser)).ToList()
            };

            return ServiceResult<UserReadDto>.Ok(userDto, "User created successfully");
        }

        public async Task<ServiceResult<TokenDto>> LoginAsync(LoginDto loginDto)
        {
            var user = await userManager.FindByEmailAsync(loginDto.Email);

            if (user == null)
            {
                return ServiceResult<TokenDto>.Fail("Invalid login Credential.");
            }

            var result = await signInManager.PasswordSignInAsync(user, loginDto.Password, loginDto.RememberMe, lockoutOnFailure: true);
            

            if (result.IsLockedOut)
                return ServiceResult<TokenDto>.Fail("Account is locked. Please try again later.");

            if (result.RequiresTwoFactor)
                return ServiceResult<TokenDto>.Fail("Two-factor authentication required.");

            if (!result.Succeeded)
                return ServiceResult<TokenDto>.Fail("Invalid login Credential.");

            var refreshToken = await GenerateRefreshTokenAsync(user);

            var jwtToken = await GenerateJWTTokenAsync(user);

            refreshToken.UserId = user.Id;

            await refreshTokenRepository.AddAsync(refreshToken);

            // إعداد Cookie آمنة
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = refreshToken.Expires
            };

            if (httpContextAccessor.HttpContext == null)
                return ServiceResult<TokenDto>.Fail("Unable to set authentication cookie.");

            // إرسال الكوكي مع الـ Refresh Token
            httpContextAccessor.HttpContext.Response.Cookies.Append("refreshToken", refreshToken.Token, cookieOptions);


            var tokenDto = new TokenDto()
            {
                AccessToken = jwtToken,
                RefreshToken = refreshToken.Token,
                ExpiresAt = refreshToken.Expires
            };
            return ServiceResult<TokenDto>.Ok(tokenDto, "User login successfully");
        }

        public async Task<ServiceResult<TokenDto>> RotateTokenAsync(string token)
        {
            //var refreshTokenFromCookies = httpContextAccessor.HttpContext!.Request.Cookies["refreshToken"];

            //if (refreshTokenFromCookies == null)
            //{
            //    return ServiceResult<TokenDto>.Fail("Refresh token is not valid.");
            //}

            var refreshToken = await refreshTokenRepository.GetByTokenAsync(token);

            if (!refreshToken.IsActive || refreshToken.IsRevoked)
            {
                return ServiceResult<TokenDto>.Fail("Refresh token has been revoked");
            }

            string ipAddress = clientInfo.GetClientIpAddress(); 

            if (refreshToken.Expires < DateTime.UtcNow)
            {
                await revocationService.RevokeTokenAsync(token, ipAddress);
                return ServiceResult<TokenDto>.Fail("Refresh token has expired");
            }


            var user = await userManager.FindByIdAsync(refreshToken.UserId);
            if (user is null)
            {
                return ServiceResult<TokenDto>.Fail("User not found");
            }


            var newJWTToken = await GenerateJWTTokenAsync(user);
            var newRefreshToken = await GenerateRefreshTokenAsync(user);


            refreshToken.IsActive = false;
            refreshToken.IsRevoked = true;
            refreshToken.RevokedAt = DateTime.UtcNow;
            refreshToken.RevokedByIp = ipAddress;
            refreshToken.RevokedReason = "Rotated";
            refreshToken.ReplacedByToken = newRefreshToken.Token;

            await refreshTokenRepository.UpdateAsync(refreshToken);


            newRefreshToken.UserId = user.Id;
            await refreshTokenRepository.AddAsync(newRefreshToken);


            if (httpContextAccessor.HttpContext == null)
                return ServiceResult<TokenDto>.Fail("Unable to set authentication cookie");


            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = newRefreshToken.Expires
            };

            httpContextAccessor.HttpContext.Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);

            var tokenDto = new TokenDto
            {
                AccessToken = newJWTToken,
                RefreshToken = newRefreshToken.Token,
                ExpiresAt = newRefreshToken.Expires
            };

            return ServiceResult<TokenDto>.Ok(tokenDto, "Token rotated successfully");
        }
       
        private async Task<string> GenerateJWTTokenAsync(IdentityUser user)
        {
            var issuer = configuration.GetSection("JwtToken:Issuer").Value;
            var audience = configuration.GetSection("JwtToken:Audience").Value;
            var jwtTokenkey = configuration.GetSection("JwtToken:key").Value;

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtTokenkey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim("AspNet.Identity.SecurityStamp", user.SecurityStamp ?? ""),
            new Claim(ClaimTypes.Name, user.UserName),
            };

            var roles = await userManager.GetRolesAsync(user);
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(15),
                signingCredentials: credentials);

            await Task.CompletedTask;
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private async Task<RefreshToken> GenerateRefreshTokenAsync(IdentityUser user)
        {

            var expirationDays = int.Parse(configuration["JwtToken:RefreshTokenExpirationDays"] ?? "7");

            var deviceType = clientInfo.GetClientInfo().DeviceType;
            var deviceId = clientInfo.GetDeviceId();
            var ipAddress =clientInfo.GetClientIpAddress();

            var randomBytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);

            RefreshToken refreshToken = new RefreshToken
            {
                UserId = user.Id,
                Token = Convert.ToBase64String(randomBytes),
                Expires = DateTime.UtcNow.AddDays(expirationDays),
                Created = DateTime.UtcNow,
                CreatedByIp = ipAddress,
                Device = deviceType,
                DeviceId = deviceId,
                IsActive = true,
                IsRevoked = false
            };

            await Task.CompletedTask;

            return (refreshToken);
        }

        public async Task<ServiceResult<string>> LogoutAsync(string userId)
        {
            var user = await userManager.FindByIdAsync(userId);

            if (user == null)
                return ServiceResult<string>.Fail("Invalid User");

            var result = await revocationService.RevokeUserTokensAsync(userId, "User Logout");

            if (result.Data > 0)
                await userManager.UpdateSecurityStampAsync(user);

            return ServiceResult<string>.Ok($"{result.Data.ToString()} Token Removed", "User Logout Successfully");
        }
    }
}