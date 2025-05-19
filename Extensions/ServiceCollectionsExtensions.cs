using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Todo.Api.Data;
using Todo.Api.Dtos.Common;
using Todo.Api.Options;
using Todo.Api.Services;
using Todo.Api.Services.Interfaces;

namespace Todo.Api.Extensions;

public static class ServiceCollectionsExtensions
{
    public static IServiceCollection AddAppOptions(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<SmtpOptions>(configuration.GetSection("Smtp"));
        services.Configure<AppSettingsOptions>(configuration.GetSection("AppSettings"));
        services.Configure<FrontendOptions>(configuration.GetSection("Frontend"));
        
        return services;
    }

    public static IServiceCollection AddAppServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddScoped<IAuthService, AuthService>();
        services.AddScoped<IAccountService, AccountService>();
        services.AddScoped<IEmailLimitService, EmailLimitService>();
        services.AddScoped<IEmailService, EmailService>();
        services.AddScoped<ITokenService, TokenService>();
        services.AddScoped<ITodoService, TodoService>();
        
        return services;
    }
    
    public static IServiceCollection AddAppDbContext(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddDbContext<TodoDbContext>(options =>
            options.UseNpgsql(configuration.GetConnectionString("DefaultConnection")));
        
        return services;
    }
    
    public static IServiceCollection AddAppAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        var appSettings = configuration
            .GetSection("AppSettings")
            .Get<AppSettingsOptions>()
            ?? throw new InvalidOperationException("JWT settings are not properly configured.");
        
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = appSettings.Issuer,
                    ValidateAudience = true,
                    ValidAudience = appSettings.Audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero,
                    IssuerSigningKey = new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(appSettings.AccessTokenKey)),
                    ValidateIssuerSigningKey = true,
                };

                options.Events = new JwtBearerEvents
                {
                    OnChallenge = context =>
                    {
                        context.HandleResponse();
                        context.Response.StatusCode = 401;
                        context.Response.ContentType = "application/json";
                        var result = ResultDto<string>.Fail(
                            "Unauthorized. You need to log in.",
                            401);
                        var json = JsonSerializer.Serialize(result);
                        return context.Response.WriteAsync(json);
                    },
                    OnForbidden = context =>
                    {
                        context.Response.StatusCode = 403;
                        context.Response.ContentType = "application/json";
                        var result = ResultDto<string>.Fail(
                            "Forbidden. You do not have permission to access this resource.",
                            403);
                        var json = JsonSerializer.Serialize(result);
                        return context.Response.WriteAsync(json);
                    }
                };
            });
        
        return services;
    }
}