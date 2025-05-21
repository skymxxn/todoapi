using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Todo.Api.Data;
using Todo.Api.Dtos.Account;
using Todo.Api.Dtos.Common;
using Todo.Api.Dtos.User;
using Todo.Api.Entities;
using Todo.Api.Options;
using Todo.Api.Services.Interfaces;

namespace Todo.Api.Services;

public class AccountService : IAccountService
{
    private readonly TodoDbContext _dbContext;
    private readonly ILogger<AccountService> _logger;
    private readonly ITokenService _tokenService;
    private readonly IEmailService _emailService;
    private readonly AppSettingsOptions _appSettings;
    private readonly IEmailLimitService _emailLimit;
    
    public AccountService(TodoDbContext dbContext, ILogger<AccountService> logger, ITokenService tokenService, IEmailService emailService, IOptions<AppSettingsOptions> appSettings, IEmailLimitService emailLimit)
    {
        _dbContext = dbContext;
        _logger = logger;
        _tokenService = tokenService;
        _emailService = emailService;
        _emailLimit = emailLimit;
        _appSettings = appSettings.Value;
    }

    public async Task<ResultDto<UserResponseDto>> GetCurrentAccount(Guid userId)
    {
        var user = await _dbContext.Users.FindAsync(userId);
        
        if (user is null)
        {
            _logger.LogWarning("User with ID {UserId} does not exist", userId);
            return ResultDto<UserResponseDto>.Fail("User not found", 404);
        }

        var userResponse = new UserResponseDto
        {
            Id = user.Id,
            Username = user.Username,
            Email = user.Email,
            IsEmailVerified = user.IsEmailVerified,
            Role = user.Role,
            Created = user.Created,
            LastLogin = user.LastLogin
        };
        
        _logger.LogInformation("Account info returned for user {Username}", user.Username);
        return ResultDto<UserResponseDto>.Ok(userResponse, message: "Account info returned successfully");
    }

    public async Task<ResultDto<string>> ChangeUserNameAsync(Guid userId, ChangeUsernameDto request)
    {
        var user = await _dbContext.Users.FindAsync(userId);
        if (user is null)
        {
            _logger.LogWarning("User with ID {UserId} does not exist", userId);
            return ResultDto<string>.Fail("User not found", 404);
        }

        if (!BCrypt.Net.BCrypt.Verify(request.CurrentPassword, user.PasswordHash))
        {
            _logger.LogWarning("Invalid password for user {Username}", user.Username);
            return ResultDto<string>.Fail("Invalid password", 401);
        }
        
        var isUsernameTaken = await _dbContext.Users
            .AnyAsync(u => u.Username.ToLower() == request.NewUsername.ToLower() 
                           && u.Id != userId);
        
        if (isUsernameTaken)
        {
            _logger.LogWarning("Username {NewUsername} is already taken", request.NewUsername);
            return ResultDto<string>.Fail("Username is already taken");
        }
        
        var oldUsername = user.Username;
        user.Username = request.NewUsername;
        
        await _dbContext.SaveChangesAsync();
        
        _logger.LogInformation("Username changed successfully for user {OldUsername} to {NewUsername}", oldUsername, request.NewUsername);
        return ResultDto<string>.Ok(message: "Username changed successfully");
    }

    public async Task<ResultDto<string>> RequestChangeEmailAsync(Guid userId, ChangeEmailDto request)
    {
        var user = await _dbContext.Users.FindAsync(userId);
        if (user is null)
        {
            _logger.LogWarning("User with ID {UserId} does not exist", userId);
            return ResultDto<string>.Fail("User not found", 404);
        }
        if (!user.IsEmailVerified)
        {
            _logger.LogWarning("User {Username} has not verified their email", user.Username);
            return ResultDto<string>.Fail("Email is not verified", 403);
        }
        
        if (user.Email.ToLower() == request.NewEmail.ToLower())
        {
            _logger.LogWarning("New email cannot be the same as the old email for user {Username}", user.Username);
            return ResultDto<string>.Fail("New email cannot be the same as the old email");
        }
        
        if (!BCrypt.Net.BCrypt.Verify(request.CurrentPassword, user.PasswordHash))
        {
            _logger.LogWarning("Invalid password for user {Username}", user.Username);
            return ResultDto<string>.Fail("Invalid password", 401);
        }
        
        var isEmailTaken = _dbContext.Users
            .Any(u => u.Email.ToLower() == request.NewEmail.ToLower()
                      && u.Id != userId);
        
        if (isEmailTaken)
        {
            _logger.LogWarning("Email {NewEmail} is already taken", request.NewEmail);
            return ResultDto<string>.Fail("Email is already taken");
        }
        
        if (!await _emailLimit.TryProcessEmailSendingAsync(user, _logger))
        {
            return ResultDto<string>.Fail("Email sending limit reached. Please try again later.");
        }
        
        var token = _tokenService.CreateEmailChangeToken(user);
        
        var emailChangeToken = new EmailChangeToken
        {
            UserId = user.Id,
            Token = token,
            NewEmail = request.NewEmail,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(_appSettings.EmailChangeTokenExpirationInMinutes),
            IsUsed = false
        };
        
        _dbContext.EmailChangeTokens.Add(emailChangeToken);
        await _dbContext.SaveChangesAsync();
        
        await _emailService.SendEmailChangeEmailAsync(user.Email, token);
        return ResultDto<string>.Ok(message: "Email change request sent successfully");
    }

    public async Task<ResultDto<string>> ChangeEmailAsync(string token)
    {
        var isTokenValid = await _tokenService.ValidateEmailChangeTokenAsync(token);
        if (!isTokenValid.Data)
        {
            _logger.LogWarning("Invalid email change token");
            return ResultDto<string>.Fail("Invalid or expired email change token");
        }
        
        var emailChangeToken = await GetEmailChangeTokenAsync(token);
        if (emailChangeToken is null)
        {
            _logger.LogWarning("Invalid email change token");
            return ResultDto<string>.Fail("Invalid or expired email change token");
        }
        
        var user = await _dbContext.Users.FindAsync(emailChangeToken.UserId);
        if (user is null)
        {
            _logger.LogWarning("User with ID {UserId} does not exist", emailChangeToken.UserId);
            return ResultDto<string>.Fail("User not found", 404);
        }
        
        var oldEmail = user.Email;
        user.Email = emailChangeToken.NewEmail;
        user.IsEmailVerified = false;
        emailChangeToken.IsUsed = true;
        await _dbContext.SaveChangesAsync();
        _logger.LogInformation("Email changed successfully from {OldEmail} to {NewEmail} for user {Username}", oldEmail,user.Email , user.Username);
        
        var emailToken = _tokenService.CreateEmailVerificationToken(user);
        await _emailService.SendVerificationEmailAsync(user.Email, emailToken);
        _logger.LogInformation("Verification email sent to {NewEmail}", user.Email);
        
        return ResultDto<string>.Ok(message: "Email changed successfully. A verification email has been sent to the new address");
    }

    private async Task<EmailChangeToken?> GetEmailChangeTokenAsync(string token)
    {
        return await _dbContext.EmailChangeTokens
            .FirstOrDefaultAsync(t => t.Token == token && !t.IsUsed && t.ExpiresAt > DateTime.UtcNow);
    }

    /// Change user password
    public async Task<ResultDto<string>> ChangePasswordAsync(Guid userId, ChangePasswordDto request)
    {
        var user = await _dbContext.Users.FindAsync(userId);
        if (user is null)
        {
            _logger.LogWarning("User with ID {UserId} does not exist", userId);
            return ResultDto<string>.Fail("User not found", 404);
        }
        
        if (!BCrypt.Net.BCrypt.Verify(request.OldPassword, user.PasswordHash))
        {
            _logger.LogWarning("Invalid old password for user {Username}", user.Username);
            return ResultDto<string>.Fail("Invalid old password", 401);
        }
        
        if (request.NewPassword == request.OldPassword)
        {
            _logger.LogWarning("New password cannot be the same as the old password for user {Username}", user.Username);
            return ResultDto<string>.Fail("New password cannot be the same as the old password");
        }
        
        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.NewPassword);
        await _dbContext.SaveChangesAsync();
        
        _logger.LogInformation("Password changed successfully for user {Username}", user.Username);
        return ResultDto<string>.Ok(message: "Password changed successfully");
    }

    public async Task<ResultDto<string>> ResendEmailConfirmationAsync(Guid userId)
    {
        var user = await _dbContext.Users.FindAsync(userId);
        if (user is null)
        {
            _logger.LogWarning("User with ID {UserId} does not exist", userId);
            return ResultDto<string>.Fail("User not found", 404);
        }
        
        if (user.IsEmailVerified)
        {
            _logger.LogWarning("User with email {Username} has already verified their email", user.Username);
            return ResultDto<string>.Fail("Email is already verified");
        }
        
        if (!await _emailLimit.TryProcessEmailSendingAsync(user, _logger))
        {
            return ResultDto<string>.Fail("Email sending limit reached. Please try again later.");
        }
        
        var emailToken = _tokenService.CreateEmailVerificationToken(user);
        await _emailService.SendVerificationEmailAsync(user.Email, emailToken);
        
        return ResultDto<string>.Ok(message: "A verification email has been sent");
    }
    
    public async Task<ResultDto<string>> DeleteAccountAsync(Guid userId)
    {
        var user = await _dbContext.Users.FindAsync(userId);
        if (user is null)
        {
            _logger.LogWarning("User with ID {UserId} does not exist", userId);
            return ResultDto<string>.Fail("User not found", 404);
        }
        
        _dbContext.Users.Remove(user);
        await _dbContext.SaveChangesAsync();
        
        _logger.LogInformation("Account {Username} deleted successfully", user.Username);
        return ResultDto<string>.Ok(message: "Account deleted successfully");
    }
}