using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using TodoApi.Data;
using TodoApi.Dtos;
using TodoApi.Entities;

namespace TodoApi.Services;

public class AuthService(TodoContext context, IConfiguration configuration) : IAuthService
{
    /// Register user and return user object
    public async Task<User?> RegisterAsync(UserDto request)
    {
        // Check if user already exists
        if (await context.Users.AnyAsync(u => u.Username == request.Username))
        {
            return null;
        }
        
        // Create new user
        var user = new User
        {
            Username = request.Username,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password)
        };
        
        // Save user to database
        context.Users.Add(user);
        await context.SaveChangesAsync();
        
        return user;
    }

    /// Login user and return access and refresh tokens
    public async Task<TokenResponseDto> LoginAsync(UserDto request)
    {
        var user = await context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
        // Check if user exists
        if (user == null)
        {
            return null;
        }
        // Check password
        if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
        {
            return null;
        }
        
        // Update last login time
        user.LastLogin = DateTime.UtcNow;
        context.Users.Update(user);
        
        return await CreateTokenResponse(user);
    }

    /// Create token response with access and refresh tokens
    private async Task<TokenResponseDto> CreateTokenResponse(User user)
    {
        var response = new TokenResponseDto
        {
            AccessToken = CreateToken(user),
            RefreshToken = await GenerateAndSaveRefreshTokenAsync(user)
        };
        return response;
    }

    /// Create JWT token
    private string CreateToken(User user)
    {
        // Create claims
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Role, user.Role)
        };
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetValue<string>("AppSettings:Token")!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);
        
        var tokenDescriptor = new JwtSecurityToken(
            issuer: configuration.GetValue<string>("AppSettings:Issuer"),
            audience: configuration.GetValue<string>("AppSettings:Audience"),
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(10),
            signingCredentials: creds
        );
        
        return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
    }
    
    /// Validate refresh token and generate new access and refresh tokens
    public async Task<TokenResponseDto> RefreshTokensAsync(RefreshTokenRequestDto request)
    {
        var user = await ValidateRefreshTokenAsync(request.UserId, request.RefreshToken);
        if (user is null)
        {
            return null;
        }
        return await CreateTokenResponse(user);
    }
    
    /// Validate refresh token and check if it is expired
    private async Task<User?> ValidateRefreshTokenAsync(Guid userId, string refreshToken)
    {
        var user = await context.Users.FindAsync(userId);
        if (user == null || user.RefreshToken != refreshToken 
                         || user.RefreshTokenExpiryTime < DateTime.UtcNow)
        {
            return null;
        }
        
        return user;
    }
    
    /// Generate a new refresh token
    private string GenerateRefreshToken()
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
        await context.SaveChangesAsync();
        return refreshToken;
    }

    /// Logout user by removing refresh token
    public async Task<bool> LogoutAsync(Guid userId)
    {
        var user = await  context.Users.FindAsync(userId);
        if (user is null) return false;
        
        user.RefreshToken = null;
        user.RefreshTokenExpiryTime = null;
        
        await context.SaveChangesAsync();
        return true;
    }
}