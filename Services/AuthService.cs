using Microsoft.EntityFrameworkCore;
using Todo.Api.Data;
using Todo.Api.Dtos.Token;
using Todo.Api.Dtos.User;
using Todo.Api.Dtos.Common;
using Todo.Api.Entities;
using Todo.Api.Services.Interfaces;

namespace Todo.Api.Services;

public class AuthService : IAuthService
{
    private readonly TodoDbContext _dbContext;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AuthService> _logger;
    private readonly IEmailService _emailService;
    private readonly ITokenService _tokenService;
    
    public AuthService(TodoDbContext dbContext, IConfiguration configuration, ILogger<AuthService> logger, IEmailService emailService, ITokenService tokenService)
    {
        _dbContext = dbContext;
        _configuration = configuration;
        _logger = logger;
        _emailService = emailService;
        _tokenService = tokenService;
    }
    
    /// Register user and return user object
    public async Task<ResultDto<UserResponseDto>> RegisterAsync(UserRegistrationDto request)
    {
        // Check if user already exists
        if (await _dbContext.Users.AnyAsync(u => u.Username == request.Username
                                               || u.Email == request.Email))
        {
            _logger.LogWarning("User with username {Username} or email {Email} already exists", request.Username, request.Email);
            return ResultDto<UserResponseDto>.Fail("User already exists");
        }
        
        // Create new user
        var user = new User
        {
            Username = request.Username,
            Email = request.Email,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password),
            Role = "User",
            Created = DateTime.UtcNow,
            LastLogin = DateTime.UtcNow
        };
        
        // Save user to database
        _dbContext.Users.Add(user);
        await _dbContext.SaveChangesAsync();
        
        _logger.LogInformation("User {Username} created successfully", request.Username);
        
        var emailToken = _tokenService.CreateEmailVerificationToken(user);
        await _emailService.SendVerificationEmailAsync(user.Email, emailToken);
        
        var userResponse = new UserResponseDto
        {
            Id = user.Id,
            Username = user.Username,
            Email = user.Email,
            IsEmailVerified = user.IsEmailVerified,
            Role = user.Role,
            Created = user.Created
        };
        
        // Return user response
        return ResultDto<UserResponseDto>.Ok(userResponse, 201);
    }
    
    
    /// Login user and return access and refresh tokens
    public async Task<ResultDto<TokenResponseDto>> LoginAsync(UserLoginDto request)
    {
        var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
        // Check if user exists and if password is correct
        if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
        {
            _logger.LogWarning("Invalid login attempt for user with email {Email}", request.Email);
            return ResultDto<TokenResponseDto>.Fail("Invalid email or password", 401);
        }
        
        if (!user.IsEmailVerified)
        {
            _logger.LogWarning("User with email {Email} has not verified their email. A verification email has been sent.", request.Email);
            
            var emailToken = _tokenService.CreateEmailVerificationToken(user);
            await _emailService.SendVerificationEmailAsync(user.Email, emailToken);
            
            return ResultDto<TokenResponseDto>.Fail("Email is not verified. A verification email has been sent.", 403);
        }
       
        // Update last login time
        user.LastLogin = DateTime.UtcNow;
        _dbContext.Users.Update(user);
        await _dbContext.SaveChangesAsync();
        
        _logger.LogInformation("User {Username} with email {Email} logged in successfully", user.Username, request.Email);
        return ResultDto<TokenResponseDto>.Ok(await _tokenService.CreateTokenResponse(user));
    }
    
    

    /// Change user password
    public async Task<ResultDto<string>> ChangePasswordAsync(Guid userId,ChangePasswordDto request)
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
        _dbContext.Users.Update(user);
        await _dbContext.SaveChangesAsync();
        
        _logger.LogInformation("Password changed successfully for user {Username}", user.Username);
        return ResultDto<string>.Ok("Password changed successfully");
    }

    /// Request password reset and send email with reset link
    public async Task<ResultDto<string>> RequestPasswordResetAsync(string email)
    {
        var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Email == email);
        if (user is null)
        {
            _logger.LogWarning("User with email {Email} does not exist", email);
            return ResultDto<string>.Fail("User not found", 404);
        }
        
        if (!user.IsEmailVerified)
        {
            _logger.LogWarning("User with email {Email} has not verified their email", email);
            return ResultDto<string>.Fail("Email is not verified. A verification email has been sent.", 403);
        }
        
        var token = _tokenService.CreatePasswordResetToken(user);
        
        var passwordResetToken = new PasswordResetToken
        {
            UserId = user.Id,
            Token = token,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(_configuration.GetValue<int>("AppSettings:PasswordResetTokenExpirationInMinutes")),
            IsUsed = false
        };
        
        _dbContext.PasswordResetTokens.Add(passwordResetToken);
        await _dbContext.SaveChangesAsync();
        
        await _emailService.SendPasswordResetEmailAsync(user.Email, token);
        
        return ResultDto<string>.Ok("Password reset email sent successfully");
    }
    

    /// Reset user password using token
    public async Task<ResultDto<string>> ResetPasswordAsync(string token, string newPassword)
    {
        var userId = await _tokenService.ValidatePasswordResetTokenAsync(token);

        var passwordResetToken = await GetPasswordResetTokenAsync(token);
        if (passwordResetToken is null)
        {
            _logger.LogWarning("Invalid or expired password reset token for user {UserId}", userId);
            return ResultDto<string>.Fail("Invalid or expired password reset token");
        }
        
        var user = await _dbContext.Users.FindAsync(passwordResetToken.UserId);
        if (user is null)
        {
            _logger.LogWarning("User with ID {UserId} does not exist", userId);
            return ResultDto<string>.Fail("User not found", 404);
        }
        
        if (!await UpdateUserPasswordAsync(user, newPassword))
        {
            _logger.LogWarning("Failed to update password for user {Username}", user.Username);
            return ResultDto<string>.Fail("Failed to update password");
        }
        
        await MarkPasswordResetTokenAsUsedAsync(passwordResetToken);

        _logger.LogInformation("Password reset successfully for user {Username}", user.Username);
        
        return ResultDto<string>.Ok("Password reset successfully");
    }
    
    private async Task<PasswordResetToken?> GetPasswordResetTokenAsync(string token)
    {
        return await _dbContext.PasswordResetTokens
            .FirstOrDefaultAsync(t => t.Token == token && !t.IsUsed && t.ExpiresAt > DateTime.UtcNow);
    }

    private async Task<bool> UpdateUserPasswordAsync(User user, string newPassword)
    {
        if (newPassword.Length < 8)
        {
            _logger.LogWarning("New password must be at least 8 characters long for user {Username}", user.Username);
            return false;
        }
        
        if (BCrypt.Net.BCrypt.Verify(newPassword, user.PasswordHash))
        {
            _logger.LogWarning("New password cannot be the same as the old password for user {Username}", user.Username);
            return false;
        }
        
        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(newPassword);
        _dbContext.Users.Update(user);
        await _dbContext.SaveChangesAsync();
        
        return true;
    }

    /// Mark password reset token as used
    private async Task MarkPasswordResetTokenAsUsedAsync(PasswordResetToken token)
    {
        token.IsUsed = true;
        _dbContext.PasswordResetTokens.Update(token);
        await _dbContext.SaveChangesAsync();
    }

    /// Logout user by removing refresh token
    public async Task<ResultDto<string>> LogoutAsync(Guid userId)
    {
        var user = await  _dbContext.Users.FindAsync(userId);
        if (user is null)
        {
            _logger.LogWarning("User with ID {UserId} does not exist", userId);
            return ResultDto<string>.Fail("User not found", 404);
        }
        
        user.RefreshToken = null;
        user.RefreshTokenExpiryTime = null;
        
        _dbContext.Users.Update(user);
        await _dbContext.SaveChangesAsync();
        
        _logger.LogInformation("User {Username} logged out successfully", user.Username);
        return ResultDto<string>.Ok("User logged out successfully");
    }
}