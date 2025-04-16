using System.Security.Claims;
using TodoApi.Dtos;
using TodoApi.Entities;

namespace TodoApi.Services;

public interface IAuthService
{
    Task<UserResponseDto> RegisterAsync(UserRegistrationDto request);
    Task<bool> VerifyEmailTokenAsync(string token);

    Task<TokenResponseDto> LoginAsync(UserLoginDto request);
    Task<TokenResponseDto> RefreshTokensAsync(RefreshTokenRequestDto request);
    Task<bool> ChangePasswordAsync(Guid userId, ChangePasswordDto request);
    Task<bool> RequestPasswordResetAsync(string email);
    Task<bool> ResetPasswordAsync(string token, string newPassword);


    Task<bool> LogoutAsync(Guid userId);
}