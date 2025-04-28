using Todo.Api.Dtos.Token;
using Todo.Api.Dtos.User;

namespace Todo.Api.Services.Interfaces;

public interface IAuthService
{
    public Task<UserResponseDto?> RegisterAsync(UserRegistrationDto request);
    public Task<bool> VerifyEmailTokenAsync(string token);
    public Task<TokenResponseDto?> LoginAsync(UserLoginDto request);
    public Task<TokenResponseDto?> RefreshTokensAsync(RefreshTokenRequestDto request);
    public Task<bool> ChangePasswordAsync(Guid userId, ChangePasswordDto request);
    public Task<bool> RequestPasswordResetAsync(string email);
    public Task<bool> ResetPasswordAsync(string token, string newPassword);
    public Task<bool> LogoutAsync(Guid userId);
}