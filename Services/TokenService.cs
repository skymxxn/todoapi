using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Todo.Api.Data;
using Todo.Api.Dtos.Common;
using Todo.Api.Dtos.Token;
using Todo.Api.Entities;
using Todo.Api.Options;
using Todo.Api.Services.Interfaces;

namespace Todo.Api.Services;

public class TokenService :ITokenService
{
    private readonly ILogger<TokenService> _logger;
    private readonly AppSettingsOptions _appSettings;
    private readonly TodoDbContext _dbContext;
    
    public TokenService(ILogger<TokenService> logger, IOptions<AppSettingsOptions> appSettings, TodoDbContext dbContext)
    {
        _logger = logger;
        _appSettings = appSettings.Value;
        _dbContext = dbContext;
    }
    
    private string CreateToken(IEnumerable<Claim> claims, string secretKey, int expirationInMinutes)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);
        
        var tokenDescriptor = new JwtSecurityToken(
            issuer: _appSettings.Issuer,
            audience: _appSettings.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(expirationInMinutes),
            signingCredentials: creds
        );
        
        return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
    }
    
    public string CreateAccessToken(User user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Role, user.Role)
        };
        
        var secretKey = _appSettings.AccessTokenKey;
        var expirationInMinutes = _appSettings.AccessTokenExpirationInMinutes;
        
        return CreateToken(claims, secretKey, expirationInMinutes);
    }
    
    private TokenValidationParameters GetTokenValidationParameters(string secretKey)
    {
        return new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
            ValidateIssuer = true,
            ValidIssuer = _appSettings.Issuer,
            ValidateAudience = true,
            ValidAudience = _appSettings.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };
    }

    public string CreateEmailVerificationToken(User user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email)
        };
        
        var secretKey = _appSettings.EmailVerificationTokenKey;
        var expirationInMinutes = _appSettings.EmailVerificationTokenExpirationInMinutes;
        
        return CreateToken(claims, secretKey, expirationInMinutes);
    }
    
    /// Validate email verification token
    public async Task<ResultDto<bool>> ValidateEmailVerificationTokenAsync(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var secretKey = _appSettings.EmailVerificationTokenKey;

        var principal = tokenHandler.ValidateToken(token, GetTokenValidationParameters(secretKey), out _);
            
        var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId is null)
        {
            _logger.LogWarning("Invalid token: User ID not found in token claims");
            return ResultDto<bool>.Fail("Invalid token");
        }
            
        var user = await _dbContext.Users.FindAsync(Guid.Parse(userId));
        if (user is null)
        {
            _logger.LogWarning("User with ID {UserId} does not exist", userId);
            return ResultDto<bool>.Fail("User not found", 404);
        }
        
        if (user.IsEmailVerified)
        {
            _logger.LogWarning("User {Username} already verified email", user.Username);
            return ResultDto<bool>.Fail("Email already verified");
        }
            
        user.IsEmailVerified = true;
        await _dbContext.SaveChangesAsync();
            
        _logger.LogInformation("User {Username} verified email successfully", user.Username);
        return ResultDto<bool>.Ok(true, message: "Email verified successfully");
    }
    
    public string CreateEmailChangeToken(User user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email)
        };
        
        var secretKey = _appSettings.EmailChangeTokenKey;
        var expirationInMinutes = _appSettings.EmailChangeTokenExpirationInMinutes;
        
        return CreateToken(claims, secretKey, expirationInMinutes);
    }

    public async Task<ResultDto<bool>> ValidateEmailChangeTokenAsync(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var secretKey = _appSettings.EmailChangeTokenKey;

        var principal = tokenHandler.ValidateToken(token, GetTokenValidationParameters(secretKey), out _);
            
        var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId is null)
        {
            _logger.LogWarning("Invalid token: User ID not found in token claims");
            return ResultDto<bool>.Fail("Invalid token");
        }
            
        var user = await _dbContext.Users.FindAsync(Guid.Parse(userId));
        if (user is null)
        {
            _logger.LogWarning("User with ID {UserId} does not exist", userId);
            return ResultDto<bool>.Fail( "User not found", 404);
        }
        
        return ResultDto<bool>.Ok(true, message: "Token is valid");
    }

    public string CreatePasswordResetToken(User user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email)
        };
        
        var secretKey = _appSettings.PasswordResetTokenKey;
        var expirationInMinutes = _appSettings.PasswordResetTokenExpirationInMinutes;
        
        return CreateToken(claims, secretKey, expirationInMinutes);
    }
    
    public async Task<ResultDto<bool>> ValidatePasswordResetTokenAsync(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var secretKey = _appSettings.PasswordResetTokenKey;
        var principal = tokenHandler.ValidateToken(token, GetTokenValidationParameters(secretKey), out _);

        var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId is null)
        {
            _logger.LogWarning("Invalid token: User ID not found in token claims");
            return ResultDto<bool>.Fail("Invalid token");
        }
        
        var user = await _dbContext.Users.FindAsync(Guid.Parse(userId));
        if (user is null)
        {
            _logger.LogWarning("User with ID {UserId} does not exist", userId);
            return ResultDto<bool>.Fail("User not found", 404);
        }
        
        return ResultDto<bool>.Ok(true, message: "Token is valid");
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
            _logger.LogError("Invalid refresh token for user with ID {UserId}", userId);
            return ResultDto<User>.Fail("Invalid refresh token", 401);
        }
        
        return ResultDto<User>.Ok(user, message: "Refresh token is valid");
    }
    
    /// Create token response with access and refresh tokens
    public async Task<TokenResponseDto> CreateTokenResponse(User user)
    {
        var response = new TokenResponseDto
        {
            AccessToken = CreateAccessToken(user),
            RefreshToken = await GenerateAndSaveRefreshTokenAsync(user)
        };
        
        return response;
    }
    
    /// Validate refresh token and generate new access and refresh tokens
    public async Task<ResultDto<TokenResponseDto>> RefreshTokensAsync(RefreshTokenRequestDto request)
    {
        var validationResult = await ValidateRefreshTokenAsync(request.UserId, request.RefreshToken);

        if (validationResult is not { Status: "Ok", Data: not null })
        {
            _logger.LogWarning("Refresh token validation failed for user {UserId}", request.UserId);
            var message = validationResult.Message ?? "Invalid refresh token";
            return ResultDto<TokenResponseDto>.Fail(message, validationResult.StatusCode);
        }

        var tokenResponse = await CreateTokenResponse(validationResult.Data);
        return ResultDto<TokenResponseDto>.Ok(tokenResponse, message: "Tokens refreshed successfully");
    }
}