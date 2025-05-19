using Todo.Api.Dtos.Common;
using Todo.Api.Entities;

namespace Todo.Api.Services.Interfaces;

public interface IEmailLimitService
{
    public Task<bool> TryProcessEmailSendingAsync(User user, ILogger logger);
    public bool CanSendEmail(User user);
    public void MarkEmailSent(User user);
}