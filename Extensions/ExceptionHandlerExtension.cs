using System.Text.Json;
using Microsoft.AspNetCore.Diagnostics;
using Todo.Api.Dtos.Common;

namespace Todo.Api.Extensions;

public static class ExceptionHandlerExtension
{
    public static void UseGlobalExceptionHandler(this WebApplication app)
    {
       app.UseExceptionHandler(errorApp =>
       {
           errorApp.Run(async context =>
           {
               var loggerFactory = app.Services.GetRequiredService<ILoggerFactory>();
               var logger = loggerFactory.CreateLogger("GlobalExceptionHandler");
               
               context.Response.StatusCode = 500;
               context.Response.ContentType = "application/json";

               var errorFeature = context.Features.Get<IExceptionHandlerFeature>();
               var exception = errorFeature?.Error;
               
               logger.LogError(exception, "Unhandled exception occurred");

               var result = new ResultDto<string>
               {
                   Status = "Fail",
                   Message = exception?.Message ?? "An unexpected error occurred.",
                   StatusCode = context.Response.StatusCode
               };
               
               var json = JsonSerializer.Serialize(result);
               await context.Response.WriteAsync(json);
           });
       });
    }
}