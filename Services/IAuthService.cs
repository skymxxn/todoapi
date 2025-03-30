using TodoApi.Dtos;
using TodoApi.Entities;

namespace TodoApi.Services;

public interface IAuthService
{
    Task<User?> RegisterAsync(UserDto request);
    Task<string> LoginAsync(UserDto request);
}