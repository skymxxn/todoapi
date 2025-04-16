namespace TodoApi.Entities;

public class PasswordResetToken
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Email { get; set; } = string.Empty;
    public string Token { get; set; } = string.Empty;
    public DateTime Expiration { get; set; }
}