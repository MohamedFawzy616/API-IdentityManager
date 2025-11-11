using IdentityManager.DTOs;
using IdentityManager.Helpers;

namespace IdentityManager.Services
{
    public interface IAuthService
    {
        public Task<ServiceResult<TokenDto>> LoginAsync(LoginDto loginDto);
        public Task<ServiceResult<UserReadDto>> CreateNewUserAsync(CreateNewUserDto createUserDto);
        public Task<ServiceResult<TokenDto>> RotateTokenAsync(string refreshToken);
        Task<ServiceResult<string>> LogoutAsync(string userId);
    }
}