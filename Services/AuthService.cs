using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
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
    
    public AuthService(TodoDbContext dbContext, IConfiguration configuration, ILogger<AuthService> logger, IEmailService emailService)
    {
        _dbContext = dbContext;
        _configuration = configuration;
        _logger = logger;
        _emailService = emailService;
    }
    
    /// Register user and return user object
    public async Task<ResultDto<UserResponseDto>> RegisterAsync(UserRegistrationDto request)
    {
        // Check if user already exists
        if (await _dbContext.Users.AnyAsync(u => u.Username == request.Username
                                               || u.Email == request.Email))
        {
            _logger.LogWarning("User with username {Username} or email {Email} already exists", request.Username, request.Email);
            return ResultDto<UserResponseDto>.Fail("User already exists", 400);
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
        
        var emailToken = CreateEmailVerificationToken(user);
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

    /// Create email verification token
    private string CreateEmailVerificationToken(User user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email)
        };
        
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["AppSettings:EmailVerificationTokenKey"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);
        
        var tokenDescriptor = new JwtSecurityToken(
            issuer: _configuration["AppSettings:Issuer"],
            audience: _configuration["AppSettings:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddDays(1),
            signingCredentials: creds
        );
        
        return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
    }
    
    /// Verify email token
    public async Task<ResultDto<string>> VerifyEmailTokenAsync(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_configuration["AppSettings:EmailVerificationTokenKey"]!);

        try
        {
            var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = _configuration["AppSettings:Issuer"],
                ValidateAudience = true,
                ValidAudience = _configuration["AppSettings:Audience"],
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);
            
            var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (userId is null)
            {
                _logger.LogWarning("Invalid token: User ID {UserId} not found", userId);
                return ResultDto<string>.Fail("Invalid token");
            }
            
            var user = await _dbContext.Users.FindAsync(Guid.Parse(userId));
            if (user is null)
            {
                _logger.LogWarning("User with ID {UserId} does not exist", userId);
                return ResultDto<string>.Fail("User not found", 404);
            }
            
            user.IsEmailVerified = true;
            await _dbContext.SaveChangesAsync();
            
            _logger.LogInformation("User {Username} verified email successfully", user.Username);
            return ResultDto<string>.Ok("Email verified successfully");
        } 
        catch (Exception ex)
        {
            _logger.LogError(ex, "Invalid email verification token");
            return ResultDto<string>.Fail("Invalid or expired token");
        }
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
            
            var emailToken = CreateEmailVerificationToken(user);
            await _emailService.SendVerificationEmailAsync(user.Email, emailToken);
            
            return ResultDto<TokenResponseDto>.Fail("Email is not verified. A verification email has been sent.", 403);
        }
       
        // Update last login time
        user.LastLogin = DateTime.UtcNow;
        _dbContext.Users.Update(user);
        await _dbContext.SaveChangesAsync();
        
        _logger.LogInformation("User {Username} with email {Email} logged in successfully", user.Username, request.Email);
        return ResultDto<TokenResponseDto>.Ok(await CreateTokenResponse(user));
    }

    /// Create token response with access and refresh tokens
    private async Task<TokenResponseDto> CreateTokenResponse(User user)
    {
        var response = new TokenResponseDto
        {
            AccessToken = CreateAccessToken(user),
            RefreshToken = await GenerateAndSaveRefreshTokenAsync(user)
        };
        
        return response;
    }

    /// Create JWT token
    private string CreateAccessToken(User user)
    {
        // Create claims
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Role, user.Role)
        };
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetValue<string>("AppSettings:AccessTokenKey")!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);
        
        var tokenDescriptor = new JwtSecurityToken(
            issuer: _configuration.GetValue<string>("AppSettings:Issuer"),
            audience: _configuration.GetValue<string>("AppSettings:Audience"),
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(20),
            signingCredentials: creds
        );
        
        return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
    }
    
    /// Validate refresh token and generate new access and refresh tokens
    public async Task<ResultDto<TokenResponseDto>> RefreshTokensAsync(RefreshTokenRequestDto request)
    {
        var user = await ValidateRefreshTokenAsync(request.UserId, request.RefreshToken);
        if (!user.Success)
        {
            _logger.LogWarning("Invalid refresh token for user {UserId}", request.UserId);
            return ResultDto<TokenResponseDto>.Fail(user.ErrorMessage!, user.StatusCode);
        }
        
        return ResultDto<TokenResponseDto>.Ok(await CreateTokenResponse(user.Data));
    }
    
    /// Validate refresh token and check if it is expired
    private async Task<ResultDto<User>> ValidateRefreshTokenAsync(Guid userId, string refreshToken)
    {
        var user = await _dbContext.Users.FindAsync(userId);
        if (user is null)
        {
            _logger.LogWarning("User with ID {UserId} does not exist", userId);
            return ResultDto<User>.Fail($"User with ID {userId} does not exist", 404);
        }
        if (user.RefreshToken != refreshToken 
                         || user.RefreshTokenExpiryTime < DateTime.UtcNow)
        {
            _logger.LogError("Invalid refresh token for user {Username}", user.Username);
            return ResultDto<User>.Fail("Invalid refresh token", 401);
        }
        
        return ResultDto<User>.Ok(user);
    }
    
    /// Generate a new refresh token
    private static string GenerateRefreshToken()
    {
        
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        
        return Convert.ToBase64String(randomNumber);
    }

    /// Generate and save refresh token to database
    private async Task<string> GenerateAndSaveRefreshTokenAsync(User user)
    {
        var refreshToken = GenerateRefreshToken();
        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
        await _dbContext.SaveChangesAsync();
        
        return refreshToken;
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
        
        var token = CreatePasswordResetToken(user);
        
        var passwordResetToken = new PasswordResetToken
        {
            UserId = user.Id,
            Token = token,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddHours(1),
            IsUsed = false
        };
        
        _dbContext.PasswordResetTokens.Add(passwordResetToken);
        await _dbContext.SaveChangesAsync();
        
        await _emailService.SendPasswordResetEmailAsync(user.Email, token);
        
        return ResultDto<string>.Ok("Password reset email sent successfully");
    }

    /// Create password reset token
    private string CreatePasswordResetToken(User user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email)
        };
        
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["AppSettings:PasswordResetTokenKey"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);
        
        var tokenDescriptor = new JwtSecurityToken(
            issuer: _configuration["AppSettings:Issuer"],
            audience: _configuration["AppSettings:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: creds
        );
        
        return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
    }

    /// Reset user password using token
    public async Task<ResultDto<string>> ResetPasswordAsync(string token, string newPassword)
    {
        var userId = await ValidatePasswordResetTokenAsync(token);
        if (userId is null)
        {
            _logger.LogWarning("Invalid or expired password reset token for user {UserId}", userId);
            return ResultDto<string>.Fail("Invalid or expired password reset token");
        }

        var passwordResetToken = await GetPasswordResetTokenAsync(token);
        if (passwordResetToken is null)
        {
            _logger.LogWarning("Invalid or expired password reset token for user {UserId}", userId);
            return ResultDto<string>.Fail("Invalid or expired password reset token");
        }
        
        var user = await _dbContext.Users.FindAsync(Guid.Parse(userId));
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

    private Task<string?> ValidatePasswordResetTokenAsync(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_configuration["AppSettings:PasswordResetTokenKey"]!);

        try
        {
            var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = _configuration["AppSettings:Issuer"],
                ValidateAudience = true,
                ValidAudience = _configuration["AppSettings:Audience"],
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);
            
            return Task.FromResult(principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Invalid password reset token");
            return Task.FromResult<string?>(null);
        }
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
        
        _logger.LogInformation("Password reset successfully for user {Username}", user.Username);
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
        
        await _dbContext.SaveChangesAsync();
        
        _logger.LogInformation("User {Username} logged out successfully", user.Username);
        return ResultDto<string>.Ok("User logged out successfully");
    }
}