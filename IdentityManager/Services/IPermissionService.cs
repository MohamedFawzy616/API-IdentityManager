using IdentityManager.DTOs;
using IdentityManager.Helpers;

namespace IdentityManager.Services
{
    public interface IPermissionService
    {
        public Task<ServiceResult<List<PermissionDto>>> GetAllPermissionsByRoleId(string id);
    }
}