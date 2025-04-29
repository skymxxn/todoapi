using Microsoft.AspNetCore.Mvc;
using Todo.Api.Dtos.Common;

namespace Todo.Api.Extensions;

public static class ResultDtoExtensions
{
    public static IActionResult ToActionResult<T>(this ResultDto<T> result)
    {
        if (result.Success)
        {
            return result.StatusCode switch
            {
                200 => new OkObjectResult(result.Data),
                201 => new CreatedResult(string.Empty, result.Data),
                204 => new NoContentResult(),
                _ => new ObjectResult(result.Data) { StatusCode = result.StatusCode }
            };
        }

        return result.StatusCode switch
        {
            400 => new BadRequestObjectResult(result.ErrorMessage),
            401 => new UnauthorizedObjectResult(result.ErrorMessage),
            403 => new ForbidResult(),
            404 => new NotFoundObjectResult(result.ErrorMessage),
            _ => new ObjectResult(result.ErrorMessage) { StatusCode = result.StatusCode }
        };
    }
}