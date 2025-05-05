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

    private async Task SendEmailAsync(string email, string emailToken, string subject, string body, string linkTemplate)
    {
        try
        {
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress("TodoApp Support", _options.Email));
            message.To.Add( new MailboxAddress(null, email));
            message.Subject = subject;
            var link = string.Format(linkTemplate, emailToken);
            message.Body = new TextPart("html")
            {
                Text = $"<h1>{subject}</h1>" +
                       $"<p>{body}</p>" +
                       $"<a href=\"{link}\">Click here</a>" +
                       $"<p>If you did not request this, please ignore this email.</p>"
            };
        
            using var client = new MailKit.Net.Smtp.SmtpClient();
            await client.ConnectAsync(_options.Host, _options.Port, MailKit.Security.SecureSocketOptions.StartTls);
            await client.AuthenticateAsync(_options.Email, _options.Password);
            await client.SendAsync(message);
            await client.DisconnectAsync(true);
            
            _logger.LogInformation("Email '{Subject}' sent to {Email}", subject, email);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending email to {Email}", email);
            throw;
        }
    }

    public async Task SendVerificationEmailAsync(string email, string emailToken)
    {
        const string body = "Please click the link below to verify your email address:";
        await SendEmailAsync(
            email, 
            emailToken, 
            "Email verification", 
            body, 
            _configuration["Frontend:EmailVerificationUrl"]!
        );
    }
    
    public async Task SendPasswordResetEmailAsync(string email, string token)
    {
        const string body = "Please click the link below to reset your password:";
        await SendEmailAsync(
            email, 
            token, 
            "Password reset", 
            body, 
            _configuration["Frontend:ResetPasswordUrl"]!
        );
    }
}