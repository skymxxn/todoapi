using Todo.Api.Dtos.Account;
using Todo.Api.Dtos.Common;
using Todo.Api.Dtos.User;

namespace Todo.Api.Services.Interfaces;

public interface IAccountService
{
    public Task<ResultDto<UserResponseDto>> GetCurrentAccount(Guid userId);
    public Task<ResultDto<string>> ChangeUserNameAsync(Guid userId, ChangeUsernameDto request);
    public Task<ResultDto<string>> RequestChangeEmailAsync(Guid userId, ChangeEmailDto request);
    public Task<ResultDto<string>> ChangeEmailAsync(string token);
    public Task<ResultDto<string>> ChangePasswordAsync(Guid userId, ChangePasswordDto request);
    public Task<ResultDto<string>> ResendEmailConfirmationAsync(Guid userId);
    public Task<ResultDto<string>> DeleteAccountAsync(Guid userId);
}