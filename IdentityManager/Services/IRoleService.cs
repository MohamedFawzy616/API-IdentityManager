using IdentityManager.DTOs;
using IdentityManager.Helpers;

namespace IdentityManager.Services
{
    public interface IRoleService
    {
        public Task<ServiceResult<RoleDto>> CreateAsync(string roleName);
        public Task<ServiceResult<List<RoleDto>>> GetAllAsync();
        public Task<ServiceResult<RoleDto>> GetByIdAsync(string id);
        public Task<ServiceResult<bool>> UpdateAsync(string id, RoleDto roleDto);
        public Task<ServiceResult<bool>> DeleteAsync(string id);
        public Task<ServiceResult<bool>> AddClaimAsync(string id, string permissionName);
        public Task<ServiceResult<bool>> RemoveClaimAsync(string id, string permissionName);
    }
}