using Serilog;
using IdentityManager.DTOs;
using Microsoft.AspNetCore.Mvc;
using IdentityManager.Services;
using Microsoft.AspNetCore.Authorization;
using Serilog.Context;

namespace IdentityManager.Controllers
{

    public class UsersController : ControllerBase
    {
        private readonly IUserService userService;
        public UsersController(IUserService _userSerive)
        {
            userService = _userSerive;
        }



        [AllowAnonymous]
        [HttpGet("api/users/index")]
        public IActionResult Index() { return Ok("working"); }



        [AllowAnonymous]
        [HttpPost("api/users/register")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<UserReadDto>> Register([FromBody] RegisterDto registerDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await userService.RegisterAsync(registerDto);

            if (!result.Success)
            {
                return BadRequest(new { result.Success, result.Message });
            }

            return Ok(new { result.Success, result.Message, result.Data });
        }



        //[Authorize]
        //[HttpGet("/api/users")]
        //[ProducesResponseType(StatusCodes.Status200OK)]
        //[ProducesResponseType(StatusCodes.Status400BadRequest)]
        //public async Task<ActionResult<List<UserReadDto>>> Get()
        //{

        //    var result = await userService.GetAllAsync();

        //    if (!result.Success)
        //    {
        //        return BadRequest(new { result.Success, result.Message });
        //    }
        //    return Ok(new { result.Success, result.Message, result.Data });
        //}



        [Authorize]
        [HttpGet("/api/users/{id}")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<UserReadDto>> GetById(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest("Invalid user id");
            }
            var result = await userService.GetByIdAsync(id);

            if (!result.Success)
            {
                return BadRequest(new { result.Success, result.Message });
            }
            return Ok(new { result.Success, result.Message, result.Data });
        }



        [Authorize]
        [HttpPut("/api/users/{id}")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<UserReadDto>> Update(string id, [FromBody] UserUpdateDto userUpdateDto)
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest("Invalid user id");
            }

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await userService.UpdateAsync(id, userUpdateDto);

            if (!result.Success)
            {
                return BadRequest(new { result.Success, result.Message });
            }
            return Ok(new { result.Success, result.Message, result.Data });
        }



        [Authorize]
        [HttpDelete("/api/users/{id}")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> Delete(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest("Invalid user id");
            }

            var result = await userService.DeleteAsync(id);
            if (!result.Success)
            {
                return BadRequest(new { result.Success, result.Message });
            }
            return Ok(new { result.Success, result.Message, result.Data });
        }
    }
}