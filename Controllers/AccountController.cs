using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Todo.Api.Dtos.Account;
using Todo.Api.Extensions;
using Todo.Api.Services.Interfaces;

namespace Todo.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class AccountController : ControllerBase
{
    private readonly IAccountService _accountService;
    
    public AccountController(IAccountService accountService)
    {
        _accountService = accountService;
    }
    
    [HttpGet("me")]
    public async Task<IActionResult> GetCurrentAccount()
    {
        var userId = User.GetUserId();
        var result = await _accountService.GetCurrentAccount(userId);
        return result.ToActionResult();
    }
    
    [HttpPost("change-username")]
    public async Task<IActionResult> ChangeUsernameAsync(ChangeUsernameDto request) {
        var userId = User.GetUserId();
        var result = await _accountService.ChangeUserNameAsync(userId, request);
        return result.ToActionResult();
    }

    [HttpPost("change-email")]
    public async Task<IActionResult> ChangeEmailAsync(ChangeEmailDto request)
    { 
        var userId = User.GetUserId();
        var result = await _accountService.RequestChangeEmailAsync(userId, request);
        return result.ToActionResult();
    }
    
    [AllowAnonymous]
    [HttpGet("confirm-email-change")]
    public async Task<IActionResult> ConfirmEmailChangeAsync([FromQuery] string token)
    {
        var result = await _accountService.ChangeEmailAsync(token);
        return result.ToActionResult();
    }
    
    [HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword(ChangePasswordDto request)
    {
        var userId = User.GetUserId();
        var result = await _accountService.ChangePasswordAsync(userId, request);
        return result.ToActionResult();
    }
}