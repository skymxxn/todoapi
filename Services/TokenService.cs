using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Todo.Api.Data;
using Todo.Api.Dtos.Common;
using Todo.Api.Dtos.Token;
using Todo.Api.Entities;
using Todo.Api.Services.Interfaces;

namespace Todo.Api.Services;

public class TokenService :ITokenService
{
    private readonly ILogger<TokenService> _logger;
    private readonly IConfiguration _configuration;
    private readonly TodoDbContext _dbContext;
    
    public TokenService(ILogger<TokenService> logger, IConfiguration configuration, TodoDbContext dbContext)
    {
        _logger = logger;
        _configuration = configuration;
        _dbContext = dbContext;
    }
    
    private string CreateToken(IEnumerable<Claim> claims, string secretKey, int expirationInMinutes)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);
        
        var tokenDescriptor = new JwtSecurityToken(
            issuer: _configuration["AppSettings:Issuer"],
            audience: _configuration["AppSettings:Audience"],
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
        
        var secretKey = _configuration["AppSettings:AccessTokenKey"]!;
        var expirationInMinutes = int.Parse(_configuration["AppSettings:AccessTokenExpirationInMinutes"]!);
        
        return CreateToken(claims, secretKey, expirationInMinutes);
    }

    public string CreateEmailVerificationToken(User user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email)
        };
        
        var secretKey = _configuration["AppSettings:EmailVerificationTokenKey"]!;
        var expirationInMinutes = int.Parse(_configuration["AppSettings:EmailVerificationTokenExpirationInMinutes"]!);
        
        return CreateToken(claims, secretKey, expirationInMinutes);
    }

    private TokenValidationParameters GetTokenValidationParameters(string secretKey)
    {
        return new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
            ValidateIssuer = true,
            ValidIssuer = _configuration["AppSettings:Issuer"],
            ValidateAudience = true,
            ValidAudience = _configuration["AppSettings:Audience"],
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };
    }
    
    /// Verify email token
    public async Task<ResultDto<string>> VerifyEmailTokenAsync(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var secretKey = _configuration["AppSettings:EmailVerificationTokenKey"]!;

        var principal = tokenHandler.ValidateToken(token, GetTokenValidationParameters(secretKey), out SecurityToken validatedToken);
            
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
        
        if (user.IsEmailVerified)
        {
            _logger.LogWarning("User {Username} already verified email", user.Username);
            return ResultDto<string>.Fail("Email already verified");
        }
            
        user.IsEmailVerified = true;
        await _dbContext.SaveChangesAsync();
            
        _logger.LogInformation("User {Username} verified email successfully", user.Username);
        return ResultDto<string>.Ok("Email verified successfully");
    }

    public string CreatePasswordResetToken(User user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email)
        };
        
        var secretKey = _configuration["AppSettings:PasswordResetTokenKey"]!;
        var expirationInMinutes = int.Parse(_configuration["AppSettings:PasswordResetTokenExpirationInMinutes"]!);
        
        return CreateToken(claims, secretKey, expirationInMinutes);
    }
    
    public async Task<ResultDto<Guid>> ValidatePasswordResetTokenAsync(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var secretKey = _configuration["AppSettings:PasswordResetTokenKey"]!;
        var principal = tokenHandler.ValidateToken(token, GetTokenValidationParameters(secretKey), out SecurityToken validatedToken);

        var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId is null)
        {
            _logger.LogWarning("Invalid token: User ID {UserId} not found", userId);
            return await Task.FromResult(ResultDto<Guid>.Fail("Invalid token"));
        }
        
        var user = await _dbContext.Users.FindAsync(Guid.Parse(userId));
        if (user is null)
        {
            _logger.LogWarning("User with ID {UserId} does not exist", userId);
            return await Task.FromResult(ResultDto<Guid>.Fail("User not found", 404));
        }
        
        return await Task.FromResult(ResultDto<Guid>.Ok(Guid.Parse(userId)));
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
            _logger.LogError("Invalid refresh token for user {Username}", user.Username);
            return ResultDto<User>.Fail("Invalid refresh token", 401);
        }
        
        return ResultDto<User>.Ok(user);
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
        var user = await ValidateRefreshTokenAsync(request.UserId, request.RefreshToken);
        if (!user.Success)
        {
            _logger.LogWarning("Invalid refresh token for user {UserId}", request.UserId);
            return ResultDto<TokenResponseDto>.Fail(user.ErrorMessage!, user.StatusCode);
        }
        
        return ResultDto<TokenResponseDto>.Ok(await CreateTokenResponse(user.Data));
    }
}