using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MimeKit;
using TodoApi.Data;
using TodoApi.Dtos;
using TodoApi.Entities;
using TodoApi.Options;

namespace TodoApi.Services;

public class AuthService(TodoContext context, IConfiguration configuration, IOptions<SmtpOptions> options) : IAuthService
{
    private readonly SmtpOptions _options = options.Value;
    /// Register user and return user object
    public async Task<UserResponseDto> RegisterAsync(UserRegistrationDto request)
    {
        // Check if user already exists
        if (await context.Users.AnyAsync(u => u.Username == request.Username
                                              || u.Email == request.Email))
        {
            return null;
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
        context.Users.Add(user);
        await context.SaveChangesAsync();
        
        var emailToken = CreateEmailVerificationToken(user);
        await SendVerificationEmailAsync(user.Email, emailToken);
        
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
        return userResponse;
    }

    /// Create email verification token
    private string CreateEmailVerificationToken(User user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email)
        };
        
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["AppSettings:EmailToken"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);
        
        var tokenDescriptor = new JwtSecurityToken(
            issuer: configuration["AppSettings:Issuer"],
            audience: configuration["AppSettings:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddDays(1),
            signingCredentials: creds
        );
        
        return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
    }
    
    /// Verify email token
    public async Task<bool> VerifyEmailTokenAsync(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(configuration["AppSettings:EmailToken"]!);

        try
        {
            var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = configuration["AppSettings:Issuer"],
                ValidateAudience = true,
                ValidAudience = configuration["AppSettings:Audience"],
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);
            var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (userId is null) return false;
            
            var user = await context.Users.FindAsync(Guid.Parse(userId));
            if (user is null) return false;
            
            user.IsEmailVerified = true;
            await context.SaveChangesAsync();
            return true;
        } 
        catch
        {
            return false;
        }
    }
   
    /// Send verification email to user
    private async Task SendVerificationEmailAsync(string email, string emailToken)
    {
        var message = new MimeMessage();
        message.From.Add(new MailboxAddress("TodoApp Support", _options.Email));
        message.To.Add( new MailboxAddress(null, email));
        message.Subject = "Email Verification";
        var verificationLink = $"http://localhost:5270/api/auth/verify-email?token={emailToken}";
        message.Body = new TextPart("html")
        {
            Text = $"<h1>Email Verification</h1>" +
                   $"<p>Please click the link below to verify your email:</p>" +
                   $"<a href=\"{verificationLink}\">Verify Email</a>" +
                   $"<p>If you did not request this, please ignore this email.</p>"
        };
        
        using var client = new MailKit.Net.Smtp.SmtpClient();
        await client.ConnectAsync(_options.Host, _options.Port, MailKit.Security.SecureSocketOptions.StartTls);
        await client.AuthenticateAsync(_options.Email, _options.Password);
        await client.SendAsync(message);
        await client.DisconnectAsync(true);
    }
    
    /// Login user and return access and refresh tokens
    public async Task<TokenResponseDto> LoginAsync(UserLoginDto request)
    {
        var user = await context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
        // Check if user exists and if password is correct
        if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
        {
            return null;
        }
        
        if (!user.IsEmailVerified)
        {
            var emailToken = CreateEmailVerificationToken(user);
            await SendVerificationEmailAsync(user.Email, emailToken);
            return null;
        }
       
        // Update last login time
        user.LastLogin = DateTime.UtcNow;
        context.Users.Update(user);
        await context.SaveChangesAsync();
        
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