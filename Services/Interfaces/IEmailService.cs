namespace Todo.Api.Services.Interfaces;

public interface IEmailService
{
    public Task SendVerificationEmailAsync(string email, string token);
    public Task SendPasswordResetEmailAsync(string email, string token);
}