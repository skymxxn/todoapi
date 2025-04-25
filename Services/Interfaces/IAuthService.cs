using Todo.Api.Dtos.Token;
using Todo.Api.Dtos.User;

namespace Todo.Api.Services.Interfaces;

public interface IAuthService
{
    Task<UserResponseDto?> RegisterAsync(UserRegistrationDto request);
    Task<bool> VerifyEmailTokenAsync(string token);

    Task<TokenResponseDto?> LoginAsync(UserLoginDto request);
    Task<TokenResponseDto?> RefreshTokensAsync(RefreshTokenRequestDto request);
    Task<bool> ChangePasswordAsync(Guid userId, ChangePasswordDto request);
    Task<bool> RequestPasswordResetAsync(string email);
    Task<bool> ResetPasswordAsync(string token, string newPassword);


    Task<bool> LogoutAsync(Guid userId);
}