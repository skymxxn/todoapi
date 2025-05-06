using Scalar.AspNetCore;
using Serilog;
using Todo.Api.Extensions;

var builder = WebApplication.CreateBuilder(args);

Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .CreateLogger();

Log.Information("Starting up!");

builder.Host.UseSerilog();

builder.Services
    .AddAppOptions(builder.Configuration)
    .AddAppDbContext(builder.Configuration)
    .AddAppAuthentication(builder.Configuration)
    .AddAppServices(builder.Configuration);

builder.Services.AddControllers();
builder.Services.AddOpenApi();

var app = builder.Build();

app.UseSerilogRequestLogging();

if (app.Environment.IsDevelopment())
{
    app.MapScalarApiReference();
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

