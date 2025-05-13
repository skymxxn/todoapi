using Microsoft.AspNetCore.Mvc;
using Todo.Api.Dtos.Common;

namespace Todo.Api.Extensions;

public static class ResultDtoExtensions
{
    public static IActionResult ToActionResult<T>(this ResultDto<T> result)
    {
        if (result.Status == "Ok")
        {
            return result.StatusCode switch
            {
                200 => new OkObjectResult(result),
                201 => new CreatedResult(string.Empty, result),
                204 => new NoContentResult(),
                _ => new ObjectResult(result) { StatusCode = result.StatusCode }
            };
        }

        return result.StatusCode switch
        {
            400 => new BadRequestObjectResult(result),
            401 => new UnauthorizedObjectResult(result),
            403 => new ForbidResult(),
            404 => new NotFoundObjectResult(result),
            _ => new ObjectResult(result) { StatusCode = result.StatusCode }
        };
    }
}