using Todo.Api.Dtos.Account;
using Todo.Api.Dtos.Common;
using Todo.Api.Dtos.Token;
using Todo.Api.Dtos.User;

namespace Todo.Api.Services.Interfaces;

public interface IAuthService
{
    public Task<ResultDto<UserResponseDto>> RegisterAsync(UserRegistrationDto request);
    public Task<ResultDto<TokenResponseDto>> LoginAsync(UserLoginDto request);
    public Task<ResultDto<string>> RequestPasswordResetAsync(string email);
    public Task<ResultDto<string>> ResetPasswordAsync(string token, string newPassword);
    public Task<ResultDto<string>> LogoutAsync(Guid userId);
}