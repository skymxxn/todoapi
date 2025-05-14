namespace Todo.Api.Dtos.User;

public class PasswordResetDto
{
    public string Token { get; set; } = string.Empty;
    public string NewPassword { get; set; } = string.Empty;
}