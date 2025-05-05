using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Todo.Api.Dtos.Token;
using Todo.Api.Dtos.User;
using Todo.Api.Extensions;
using Todo.Api.Services.Interfaces;

namespace Todo.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly ITokenService _tokenService;
    public AuthController(IAuthService authService, ITokenService tokenService)
    {
        _authService = authService;
        _tokenService = tokenService;
    }
    
    [HttpPost("register")]
    public async Task<IActionResult> Register(UserRegistrationDto request)
    {
        var result = await _authService.RegisterAsync(request);
        return result.ToActionResult();
    }
    
    [HttpGet("verify-email")]
    public async Task<IActionResult> VerifyEmail([FromQuery] string token)
    {
        var result = await _tokenService.VerifyEmailTokenAsync(token);

        return result.ToActionResult();
    }
    
    [HttpPost("login")]
    public async Task<IActionResult> Login(UserLoginDto request)
    {
        var result = await _authService.LoginAsync(request);
        return result.ToActionResult();
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken(RefreshTokenRequestDto request)
    {
        var result = await _tokenService.RefreshTokensAsync(request);
        return result.ToActionResult();
    }

    [HttpPost("change-password")]
    [Authorize]
    public async Task<IActionResult> ChangePassword(ChangePasswordDto request)
    {
        var result = await _authService.ChangePasswordAsync(
            Guid.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? string.Empty), request);
        return result.ToActionResult();
    }

    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordDto request)
    {
        var result = await _authService.RequestPasswordResetAsync(request.Email);
        return result.ToActionResult();
    }
    
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword(PasswordResetDto request)
    {
        var result = await _authService.ResetPasswordAsync(request.Token, request.NewPassword);
        return result.ToActionResult();
    }
    
    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId is null) return Unauthorized();
        
        var result = await _authService.LogoutAsync(Guid.Parse(userId));
        return result.ToActionResult();
    }
}