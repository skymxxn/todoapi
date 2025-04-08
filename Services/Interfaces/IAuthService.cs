using TodoApi.Dtos;
using TodoApi.Entities;

namespace TodoApi.Services;

public interface IAuthService
{
    Task<User?> RegisterAsync(UserDto request);
    Task<TokenResponseDto> LoginAsync(UserDto request);
    Task<TokenResponseDto> RefreshTokensAsync(RefreshTokenRequestDto request);
    Task<bool> LogoutAsync(Guid userId);
}