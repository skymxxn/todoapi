using System.Security.Claims;

namespace Todo.Api.Extensions;

public static class ClaimsPrincipalExtensions
{
    public static Guid GetUserId(this ClaimsPrincipal principal)
    {
        var id = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        return Guid.TryParse(id, out var guid) ? guid : Guid.Empty;
    }
}