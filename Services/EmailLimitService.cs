using Todo.Api.Data;
using Todo.Api.Dtos.Common;
using Todo.Api.Entities;
using Todo.Api.Services.Interfaces;

namespace Todo.Api.Services;

public class EmailLimitService : IEmailLimitService
{
    private readonly TimeSpan _cooldown = TimeSpan.FromMinutes(5);
    private readonly TodoDbContext _dbContext;

    public EmailLimitService(TodoDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<bool> TryProcessEmailSendingAsync(User user, ILogger logger)
    {
        if (!CanSendEmail(user))
        {
            logger.LogWarning("Email sending limit reached for user {Username}", user.Username);
            return false;
        }
        
        MarkEmailSent(user);
        await _dbContext.SaveChangesAsync();
        return true;
    }

    public bool CanSendEmail(User user)
    {
        return user.LastEmailSentAt == null || 
               DateTime.UtcNow - user.LastEmailSentAt > _cooldown;
    }

    public void MarkEmailSent(User user)
    {
        user.LastEmailSentAt = DateTime.UtcNow;
    }
}