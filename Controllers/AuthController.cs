using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Todo.Api.Data;
using Todo.Api.Dtos;
using Todo.Api.Dtos.Token;
using Todo.Api.Dtos.User;
using Todo.Api.Services;
using Todo.Api.Entities;
using Todo.Api.Services.Interfaces;

namespace Todo.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly TodoDbContext _dbContext;
    public AuthController(IAuthService authService, TodoDbContext dbContext)
    {
        _dbContext = dbContext;
        _authService = authService;
    }
    [HttpPost("register")]
    public async Task<ActionResult<UserLoginDto>> Register(UserRegistrationDto request)
    {
        var user = await _authService.RegisterAsync(request);
        if (user == null)
        {
            return BadRequest("User with the same email or username already exists.");
        }
        return Ok(user);
    }
    
    [HttpGet("verify-email")]
    public async Task<IActionResult> VerifyEmail([FromQuery] string token)
    {
        var result = await _authService.VerifyEmailTokenAsync(token);
        if (!result)
            return BadRequest("Invalid or expired token.");

        return Ok("Email verified successfully.");
    }
    
    [HttpPost("login")]
    public async Task<ActionResult<TokenResponseDto>> Login(UserLoginDto request)
    {
        var response = await _authService.LoginAsync(request);
        if (response is null)
        {
            return BadRequest("Invalid email or password.");
        }
        return Ok(response);
    }

    [HttpPost("refresh-token")]
    public async Task<ActionResult<TokenResponseDto>> RefreshToken(RefreshTokenRequestDto request)
    {
        var response = await _authService.RefreshTokensAsync(request);
        if (response is null || response.RefreshToken is null || response.AccessToken is null)
        {
            return Unauthorized("Invalid refresh token.");
        }
        return Ok(response);
    }

    [HttpPost("change-password")]
    [Authorize]
    public async Task<IActionResult> ChangePassword(ChangePasswordDto request)
    {
        var result = await _authService.ChangePasswordAsync(
            Guid.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? string.Empty), request);
        if (!result)
        {
            return BadRequest("Failed to change password.");
        }
        return Ok("Password changed successfully.");
    }

    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordDto request)
    {
        var result = await _authService.RequestPasswordResetAsync(request.Email);
        if (!result) return BadRequest("User not found or email is not verified.");
        
        return Ok("Password reset email sent.");
    }
    
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword(PasswordResetDto request)
    {
        var result = await _authService.ResetPasswordAsync(request.Token, request.NewPassword);
        if (!result) return BadRequest("Invalid or expired token.");
        
        return Ok("Password reset successfully.");
    }
    
    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId is null) return Unauthorized();
        
        bool result = await _authService.LogoutAsync(Guid.Parse(userId));
        if (!result) return BadRequest("Logout failed.");
        
        return Ok("Logout successful.");
    }
}