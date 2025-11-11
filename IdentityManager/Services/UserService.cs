using IdentityManager.DTOs;
using IdentityManager.Helpers;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Data;
using System.Security.Claims;

namespace IdentityManager.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;

        public UserService(UserManager<IdentityUser> _userManager, RoleManager<IdentityRole> _roleManager)
        {
            userManager = _userManager;
            roleManager = _roleManager;
        }

        public async Task<ServiceResult<UserReadDto>> RegisterAsync(RegisterDto registerDto)
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


            string role = "user";
            if (!await roleManager.RoleExistsAsync(role))
            {
                await roleManager.CreateAsync(new IdentityRole() { Name = role });
            }

            var addRoleResult = await userManager.AddToRoleAsync(newUser, role);
            if (!addRoleResult.Succeeded)
            {
                return ServiceResult<UserReadDto>.Fail($"Failed to assign role '{role}'");
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

        public async Task<ServiceResult<List<UserReadDto>>> GetAllAsync()
        {
            var users = await userManager.Users.ToListAsync();

            var userDtos = new List<UserReadDto>();

            foreach (var user in users)
            {
                userDtos.Add(new UserReadDto
                {
                    Id = user.Id,
                    Email = user.Email,
                    Roles = (await userManager.GetRolesAsync(user)).ToList()
                });
            }
            return ServiceResult<List<UserReadDto>>.Ok(userDtos);
        }

        public async Task<ServiceResult<UserReadDto>> GetByIdAsync(string id)
        {
            var user = await userManager.FindByIdAsync(id);

            if (user == null)
            {
                return ServiceResult<UserReadDto>.Fail("User not found");
            }

            UserReadDto userDto = new UserReadDto
            {
                Id = user.Id,
                Email = user.Email,
                Roles = (await userManager.GetRolesAsync(user)).ToList()
            };

            return ServiceResult<UserReadDto>.Ok(userDto);
        }

        public async Task<ServiceResult<bool>> AddToRoleAsync(string userId, string roleName)
        {

            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return ServiceResult<bool>.Fail("User Not Found.");
            }

            if (!await roleManager.RoleExistsAsync(roleName))
            {
                return ServiceResult<bool>.Fail("Role Not Found.");
            }


            var result = await userManager.AddToRoleAsync(user, roleName);

            if (!result.Succeeded == true)
            {
                return ServiceResult<bool>.Fail(string.Join(", ", result.Errors.Select(e => e.Description)));
            }
            return ServiceResult<bool>.Ok(true, "Role Added to User");
        }

        public async Task<ServiceResult<bool>> RemoveFromRoleAsync(string userId, string roleName)
        {
            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return ServiceResult<bool>.Fail("User Not Found.");
            }

            if (!await roleManager.RoleExistsAsync(roleName))
            {
                return ServiceResult<bool>.Fail("Role Not Found.");
            }

            var result = await userManager.RemoveFromRoleAsync(user, roleName);

            if (!result.Succeeded == true)
            {
                return ServiceResult<bool>.Fail(string.Join(", ", result.Errors.Select(e => e.Description)));
            }

            return ServiceResult<bool>.Ok(true, "Role Removed From User");
        }

        public async Task<ServiceResult<bool>> AddClaimAsync(string userId, string claimName)
        {
            var user = await userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return ServiceResult<bool>.Fail("User Not Found.");
            }

            var ClaimExsitsInUser = (await userManager.GetClaimsAsync(user)).FirstOrDefault(c => c.ValueType == "Permission" && c.Value == claimName);
            if (ClaimExsitsInUser != null)
            {
                return ServiceResult<bool>.Fail("Claim Already Exists in User.");
            }

            var claim = new Claim("Permission", claimName);

            var result = await userManager.AddClaimAsync(user, claim);
            if (!result.Succeeded == true)
            {
                var errors = result.Errors.Select(result => result.Description);
                return ServiceResult<bool>.Fail(string.Join(", ", errors));
            }
            return ServiceResult<bool>.Ok(true, "Claim Added to the user");
        }

        public async Task<ServiceResult<bool>> RemoveClaimAsync(string userId, string claimName)
        {
            var user = await userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return ServiceResult<bool>.Fail("User Not Found.");
            }

            var ClaimExsitsInUser = (await userManager.GetClaimsAsync(user)).FirstOrDefault(c => c.ValueType == "Permission" && c.Value == claimName);
            if (ClaimExsitsInUser == null)
            {
                return ServiceResult<bool>.Fail("Claim not Exists at User.");
            }

            var claim = new Claim("Permission", claimName);

            var result = await userManager.RemoveClaimAsync(user, claim);
            if (!result.Succeeded == true)
            {
                var errors = result.Errors.Select(result => result.Description);
                return ServiceResult<bool>.Fail(string.Join(", ", errors));
            }
            return ServiceResult<bool>.Ok(true, "Claim Removed from the user");
        }
        
        public async Task<ServiceResult<UserReadDto>> CreateAsync(UserCreateDto createUserDto)
        {
            var existUser = await userManager.FindByEmailAsync(createUserDto.Email);

            if (existUser != null)
            {
                return ServiceResult<UserReadDto>.Fail("User already exists");
            }

            var newUser = new IdentityUser()
            {
                UserName = createUserDto.Name,
                Email = createUserDto.Email
            };

            var result = await userManager.CreateAsync(newUser, createUserDto.Password);

            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                return ServiceResult<UserReadDto>.Fail(errors);
            }

            if (createUserDto.Roles.Count > 0)
            {
                foreach (var role in createUserDto.Roles)
                {
                    if (await roleManager.RoleExistsAsync(role))
                    {
                        await userManager.AddToRoleAsync(newUser, role);
                    }
                }
            }

            UserReadDto userDto = new UserReadDto()
            {
                Id = newUser.Id,
                Email = newUser.Email,
                Roles = (await userManager.GetRolesAsync(newUser)).ToList()
            };

            return ServiceResult<UserReadDto>.Ok(userDto, "User created successfully");
        }
        
        public async Task<ServiceResult<UserReadDto>> UpdateAsync(string id, UserUpdateDto userUpdateDto)
        {
            var user = await userManager.FindByIdAsync(id);
            if (user == null)
            {
                return ServiceResult<UserReadDto>.Fail("User Not Found.");
            }


            if (userUpdateDto == null)
            {
                return ServiceResult<UserReadDto>.Fail("User Not Found.");
            }

            user.UserName = userUpdateDto.Name;

            var result = await userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                return ServiceResult<UserReadDto>.Fail(string.Join(", ", result.Errors.Select(e => e.Description)));
            }

            var readUserDto = new UserReadDto()
            {
                Id = user.Id,
                UserName = user.UserName,
                Email = user.Email,
                Roles = (await userManager.GetRolesAsync(user)).ToList()
            };

            return ServiceResult<UserReadDto>.Ok(readUserDto);
        }
        
        public async Task<ServiceResult<bool>> DeleteAsync(string id)
        {
            var user = await userManager.FindByIdAsync(id);

            if (user == null)
            {
                return ServiceResult<bool>.Fail("User doesn't exists");
            }

            var result = await userManager.DeleteAsync(user);

            if (!result.Succeeded == true)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                return ServiceResult<bool>.Fail(errors);
            }

            return ServiceResult<bool>.Ok(true, "User Deleted Successfully");
        }
    }
}