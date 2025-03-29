using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using TodoApi.Data;
using TodoApi.Dtos;
using TodoApi.Entities;

namespace TodoApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController(TodoContext context, IConfiguration configuration) : ControllerBase
{

    [HttpPost("register")]
    public async Task<ActionResult> Register(UserDto request)
    {
        if (await context.Users.AnyAsync(u => u.Username == request.Username))
        {
            return BadRequest("Username already exists");
        }
        
        var user = new User
        {
            Username = request.Username,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password)
        };
        
        context.Users.Add(user);
        await context.SaveChangesAsync();

        return Ok(user);
    }
    
    [HttpPost("login")]
    public async Task<ActionResult<string>> Login(UserDto request)
    {
        var user = await context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
        if (user == null)
        {
            return BadRequest("User not found");
        }
        
        if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
        {
            return BadRequest("Invalid password");
        }

        string token = CreateToken(user);

        return Ok(token);
    }
    
    private string CreateToken(User user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
        };
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetValue<string>("AppSettings:Token")!));
        
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);
        
        var tokenDescriptor = new JwtSecurityToken(
            issuer: configuration.GetValue<string>("AppSettings:Issuer"),
            audience: configuration.GetValue<string>("AppSettings:Audience"),
            claims: claims,
            expires: DateTime.UtcNow.AddDays(1),
            signingCredentials: creds
        );
        
        return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
    }
    
}