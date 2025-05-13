using System.Security.Claims;

namespace Todo.Api.Middlewares;

public class RateLimitClientIdMiddleware
{
    private readonly RequestDelegate _next;

    public RateLimitClientIdMiddleware(RequestDelegate next)
    {
        _next = next;
    }
    
    public async Task InvokeAsync(HttpContext context)
    {
        if (context.User.Identity?.IsAuthenticated == true)
        {
            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            
            if (!string.IsNullOrEmpty(userId))
            {
                context.Request.Headers["ClientId"] = userId;
            }
        }
        
        await _next(context);
    }
}