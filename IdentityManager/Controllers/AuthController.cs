using Serilog;
using IdentityManager.DTOs;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using IdentityManager.Services;
using Microsoft.AspNetCore.Authorization;

namespace IdentityManager.Controllers
{
    public class AuthController : Controller
    {
        private readonly IAuthService authService;
        private readonly IPasswordService passwordService;
        private readonly ITokenRevocationService tokenRevocationService;
        public AuthController(IAuthService _authService, IPasswordService _passwordService, ITokenRevocationService _tokenRevocationService)
        {
            authService = _authService;
            passwordService = _passwordService;
            tokenRevocationService = _tokenRevocationService;
        }


        [HttpGet("api/auth/index")]
        public IActionResult Index() { return Ok("working"); }


        [Authorize(Roles ="admin")]
        [HttpPost("api/auth/CreateNewUser")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<UserReadDto>> CreateNewUser([FromBody] CreateNewUserDto registerDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await authService.CreateNewUserAsync(registerDto);

            if (!result.Success)
                return BadRequest(new { result.Success, result.Message });

            return Ok(new { result.Success, result.Message, result.Data });
        }


        [AllowAnonymous]
        [HttpPost("api/auth/login")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await authService.LoginAsync(loginDto);

            if (!result.Success)
                return BadRequest(new { result.Success, result.Message });

            return Ok(new { result.Success, result.Message, result.Data });
        }




        [HttpPost("api/auth/RotateToken")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> RotateToken([FromBody] RefreshRequestDto refreshRequestDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await authService.RotateTokenAsync(refreshRequestDto.token);

            if (!result.Success)
            {
                return BadRequest(new { result.Success, result.Message });
            }

            return Ok(new { result.Success, result.Message, result.Data });
        }



        #region Revoked

        [Authorize]
        [HttpPost("api/auth/RevokeToken")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> RevokeToken([FromBody] RevokeTokenDto revokeTokenDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null)
            {
                return Unauthorized(new { message = "User not authenticated" });
            }

            var result = await tokenRevocationService.RevokeTokenAsync(revokeTokenDto.token, userId, "Manual revocation");

            if (!result.Success)
            {
                return BadRequest(new { result.Success, result.Message });
            }

            return Ok(new { result.Success, result.Message, result.Data });
        }


        [Authorize(Roles = "admin")]
        [HttpPost("api/auth/RevokeAll")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> RevokeAllUserToken()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (userId == null)
            {
                return Unauthorized(new { message = "User not authenticated" });
            }

            var result = await tokenRevocationService.RevokeUserTokensAsync(userId, "User requested logout from all devices");
            if (!result.Success)
            {
                return BadRequest(new { result.Success, result.Message });
            }

            return Ok(new { result.Success, result.Message, result.Data });
        }



        [Authorize(Roles = "admin")]
        [HttpPost("api/auth/RevokeDeviceTokens")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> RevokeDeviceTokens([FromBody] string deviceId)
        {
            if (string.IsNullOrWhiteSpace(deviceId))
            {
                return BadRequest(new { message = "Device Id is required" });
            }

            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized(new { message = "User not authenticated" });
            }

            var result = await tokenRevocationService.RevokeTokensByDeviceAsync(userId, deviceId, $"User request revoke for device: {deviceId}");

            if (!result.Success)
            {
                return BadRequest(new { result.Success, result.Message });
            }

            return Ok(new { result.Success, result.Message, result.Data });
        }



        [Authorize(Roles = "admin")]
        [HttpGet("api/auth/GetActiveSessions")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> GetActiveSessions()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized(new { message = "User not authenticated" });
            }

            var result = await tokenRevocationService.GetActiveSessions(userId);

            if (!result.Success)
            {
                return BadRequest(new { result.Success, result.Message, result.Data });
            }

            return Ok(new { sessions = result, count = result.Data.Count });
        }
        #endregion


        #region Password EndPoinds

        /// <summary>
        /// Change password for authenticated user
        /// </summary>
        [Authorize]
        [HttpPost("api/auth/ChangePassword")]
        [ProducesResponseType(typeof(ChangePasswordResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequestDto requestDto)
        {
            if (ModelState.IsValid == false)
            {
                return BadRequest(ModelState);
            }

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized("User not authenticated");
            }

            var result = await passwordService.ChangePasswordAsync(userId, requestDto.CurrentPassword, requestDto.NewPassword, requestDto.RevokeAllTokens);

            if (!result.Success)
            {
                return BadRequest(new { result.Success, result.Message });
            }

            return Ok(new { result.Success, result.Message, result.Data });
        }



        /// <summary>
        /// Request password reset (forgot password)
        /// </summary>
        [AllowAnonymous]
        [HttpPost("api/auth/ForgetPassword")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> ForgetPassword([FromBody] ForgotPasswordRequestDto requestDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await passwordService.GeneratePasswordResetTokenAsync(requestDto.Email);

            if (!result.Success)
            {
                return BadRequest(new { result.Success, result.Message });
            }

            return Ok(new { result.Success, result.Message, result.Data });
        }



        /// <summary>
        /// Reset password using reset token
        /// </summary>
        [AllowAnonymous]
        [HttpPost("api/auth/ResetPassword")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequestDto requestDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await passwordService.ResetPasswordAsync(requestDto.Email, requestDto.ResetToken, requestDto.NewPassword);

            if (!result.Success)
            {
                return BadRequest(new { result.Success, result.Message });
            }

            return Ok(new { result.Success, result.Message, result.Data });
        }



        /// <summary>
        /// Validate if current password is correct (useful for confirmation dialogs)
        /// </summary>
        [Authorize]
        [HttpPost("validate")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> ValidPassword(ValidatePasswordDto passwordDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized("User not authenticated");
            }

            var result = await passwordService.ValidatePasswordAsync(userId, passwordDto.Password);

            if (!result.Success)
            {
                return BadRequest(new { result.Success, result.Message });
            }

            return Ok(new { result.Success, result.Message, result.Data });
        }
        #endregion Password



        [Authorize]
        [HttpPost("api/auth/logout")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> Logout()
        {
            string userId = User.FindFirstValue(ClaimTypes.NameIdentifier)!;

            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized("User not authenticated");
            }

            var result = await authService.LogoutAsync(userId);

            if (!result.Success)
            {
                return BadRequest(new { result.Success, result.Message });
            }

            return Ok(new { result.Success, result.Message, result.Data });
        }
    }
}