using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MimeKit;
using TodoApi.Data;
using TodoApi.Dtos;
using TodoApi.Entities;
using TodoApi.Options;

namespace TodoApi.Services;

public class AuthService : IAuthService
{
    private readonly TodoContext _context;
    private readonly IConfiguration _configuration;
    private readonly SmtpOptions _options;
    
    public AuthService(TodoContext context, IConfiguration configuration, IOptions<SmtpOptions> options)
    {
        _context = context;
        _configuration = configuration;
        _options = options.Value;
    }
    /// Register user and return user object
    public async Task<UserResponseDto> RegisterAsync(UserRegistrationDto request)
    {
        // Check if user already exists
        if (await _context.Users.AnyAsync(u => u.Username == request.Username
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
        _context.Users.Add(user);
        await _context.SaveChangesAsync();
        
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
        
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["AppSettings:EmailToken"]!));
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
    public async Task<bool> VerifyEmailTokenAsync(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_configuration["AppSettings:EmailToken"]!);

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
            if (userId is null) return false;
            
            var user = await _context.Users.FindAsync(Guid.Parse(userId));
            if (user is null) return false;
            
            user.IsEmailVerified = true;
            await _context.SaveChangesAsync();
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
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
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
        _context.Users.Update(user);
        await _context.SaveChangesAsync();
        
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
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetValue<string>("AppSettings:Token")!));
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
        var user = await _context.Users.FindAsync(userId);
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
        await _context.SaveChangesAsync();
        return refreshToken;
    }

    /// Change user password
    public async Task<bool> ChangePasswordAsync(Guid userId,ChangePasswordDto request)
    {
        var user = await _context.Users.FindAsync(userId);
        if (user is null) return false;
        
        if (!BCrypt.Net.BCrypt.Verify(request.OldPassword, user.PasswordHash))
        {
            return false;
        }
        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.NewPassword);
        _context.Users.Update(user);
        await _context.SaveChangesAsync();
        return true;
    }

    /// Request password reset and send email with reset link
    public async Task<bool> RequestPasswordResetAsync(string email)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
        if (user is null || !user.IsEmailVerified) return false;
        
        var token = CreatePasswordResetToken(user);
        await SendPasswordResetEmailAsync(user.Email, token);
        return true;
    }

    /// Create password reset token
    private string CreatePasswordResetToken(User user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email)
        };
        
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["AppSettings:EmailToken"]!));
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
    
    /// Send password reset email to user
    private async Task SendPasswordResetEmailAsync(string email, string token)
    {
        var message = new MimeMessage();
        message.From.Add(new MailboxAddress("TodoApp Support", _options.Email));
        message.To.Add( new MailboxAddress(null, email));
        message.Subject = "Password Reset";
        var resetLink = $"http://localhost:5270/api/auth/reset-password?token={token}";
        message.Body = new TextPart("html")
        {
            Text = $"<h1>Password Reset</h1>" +
                   $"<p>Please click the link below to reset your password:</p>" +
                   $"<a href=\"{resetLink}\">Reset Password</a>" +
                   $"<p>If you did not request this, please ignore this email.</p>"
        };
        
        using var client = new MailKit.Net.Smtp.SmtpClient();
        await client.ConnectAsync(_options.Host, _options.Port, MailKit.Security.SecureSocketOptions.StartTls);
        await client.AuthenticateAsync(_options.Email, _options.Password);
        await client.SendAsync(message);
        await client.DisconnectAsync(true);
    }

    /// Reset user password using token
    public async Task<bool> ResetPasswordAsync(string token, string newPassword)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_configuration["AppSettings:EmailToken"]!);

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
            if (userId is null) return false;
            
            var user = await _context.Users.FindAsync(Guid.Parse(userId));
            if (user is null) return false;
            
            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(newPassword);
            await _context.SaveChangesAsync();
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// Logout user by removing refresh token
    public async Task<bool> LogoutAsync(Guid userId)
    {
        var user = await  _context.Users.FindAsync(userId);
        if (user is null) return false;
        
        user.RefreshToken = null;
        user.RefreshTokenExpiryTime = null;
        
        await _context.SaveChangesAsync();
        return true;
    }
}