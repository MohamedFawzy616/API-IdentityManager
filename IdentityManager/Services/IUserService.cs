using IdentityManager.DTOs;
using IdentityManager.Helpers;
using IdentityManager.Models;
using Microsoft.AspNetCore.Identity;

namespace IdentityManager.Services
{
    public interface IUserService
    {
        public Task<ServiceResult<UserReadDto>> RegisterAsync(RegisterDto registerDto);
        public Task<ServiceResult<UserReadDto>> UpdateAsync(string id, UserUpdateDto userUpdateDto);
        public Task<ServiceResult<List<UserReadDto>>> GetAllAsync();
        public Task<ServiceResult<UserReadDto>> GetByIdAsync(string Id);
        public Task<ServiceResult<bool>> DeleteAsync(string id);
        public Task<ServiceResult<bool>> AddToRoleAsync(string userId, string roleName);
        public Task<ServiceResult<bool>> RemoveFromRoleAsync(string userId, string roleName);
        public Task<ServiceResult<bool>> AddClaimAsync(string userId, string claimName);
        public Task<ServiceResult<bool>> RemoveClaimAsync(string userId, string claimName);
    }
}