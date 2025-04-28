using Microsoft.Extensions.Options;
using MimeKit;
using Todo.Api.Options;
using Todo.Api.Services.Interfaces;

namespace Todo.Api.Services;

public class EmailService : IEmailService
{
    private readonly ILogger<EmailService> _logger;
    private readonly SmtpOptions _options;
    private readonly IConfiguration _configuration;
    
    public EmailService(ILogger<EmailService> logger, IOptions<SmtpOptions> options, IConfiguration configuration)
    {
        _logger = logger;
        _options = options.Value;
        _configuration = configuration;
    }

    public async Task SendVerificationEmailAsync(string email, string emailToken)
    {
        try
        {
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress("TodoApp Support", _options.Email));
            message.To.Add( new MailboxAddress(null, email));
            message.Subject = "Email Verification";
            var verificationLink = string.Format(_configuration["Frontend:VerificationUrl"]!, emailToken);
            message.Body = new TextPart("html")
            {
                Text = $"<h1>Email Verification</h1>" +
                       $"<p>Please click the link below to verify your email:</p>" +
                       $"<a href=\"{verificationLink}\">Verify Email</a>" +
                       $"<p>If you did not request this, please ignore this email.</p>"
            };
        
            using var client = new MailKit.Net.Smtp.SmtpClient();
            await client.ConnectAsync(_options.Host, _options.Port, MailKit.Security.SecureSocketOptions.StartTls);
            await client.AuthenticateAsync(_options.Email, _options.Password);
            await client.SendAsync(message);
            await client.DisconnectAsync(true);
        
            _logger.LogInformation("Verification email sent to {Email}", email);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending verification email");
            throw;
        }
    }
    
    public async Task SendPasswordResetEmailAsync(string email, string token)
    {
        try
        {
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress("TodoApp Support", _options.Email));
            message.To.Add( new MailboxAddress(null, email));
            message.Subject = "Password Reset";
            var resetLink = string.Format(_configuration["Frontend:ResetPasswordUrl"]!, token);
            message.Body = new TextPart("html")
            {
                Text = $"<h1>Password Reset</h1>" +
                       $"<p>Please click the link below to reset your password:</p>" +
                       $"<a href=\"{resetLink}\">Reset Password</a>" +
                       $"<p>If you did not request this, please ignore this email.</p>"
            };
        
            using var client = new MailKit.Net.Smtp.SmtpClient();
            await client.ConnectAsync(_options.Host, _options.Port, MailKit.Security.SecureSocketOptions.StartTls);
            await client.AuthenticateAsync(_options.Email, _options.Password);
            await client.SendAsync(message);
            await client.DisconnectAsync(true);
        
            _logger.LogInformation("Password reset email sent to {Email}", email);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending password reset email to {Email}", email);
            throw;
        }
    }
}