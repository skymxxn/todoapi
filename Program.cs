using AspNetCoreRateLimit;
using Scalar.AspNetCore;
using Serilog;
using Todo.Api.Extensions;
using Todo.Api.Middlewares;

var builder = WebApplication.CreateBuilder(args);

// ---------- Logging ----------
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .CreateLogger();
Log.Information("Starting up!");
builder.Host.UseSerilog();

// ---------- Configuration & Services ----------
builder.Services
    .AddAppOptions(builder.Configuration)
    .AddAppDbContext(builder.Configuration)
    .AddAppAuthentication(builder.Configuration)
    .AddAppServices(builder.Configuration);

// ---------- MVC & Swagger ----------
builder.Services.AddControllers();
builder.Services.AddOpenApi();

// ---------- Rate Limiting ----------
builder.Services.AddMemoryCache();
builder.Services.Configure<IpRateLimitOptions>(builder.Configuration.GetSection("IpRateLimiting"));
builder.Services.Configure<ClientRateLimitOptions>(builder.Configuration.GetSection("ClientRateLimiting"));
builder.Services.Configure<ClientRateLimitPolicies>(builder.Configuration.GetSection("ClientRateLimitPolicies"));

builder.Services.AddSingleton<IRateLimitCounterStore, MemoryCacheRateLimitCounterStore>();
builder.Services.AddSingleton<IClientPolicyStore, MemoryCacheClientPolicyStore>();
builder.Services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();
builder.Services.AddSingleton<IProcessingStrategy, AsyncKeyLockProcessingStrategy>();

// ---------- Misc ----------
builder.Services.AddHttpContextAccessor();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapScalarApiReference();
    app.MapOpenApi();
}

// ---------- Middleware ----------
app.UseSerilogRequestLogging();

// ---------- Security ----------
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();


// ---------- Rate Limiting ----------
app.UseMiddleware<RateLimitClientIdMiddleware>();
app.UseClientRateLimiting();

// ---------- Global Exception Handling ----------
app.UseGlobalExceptionHandler();

// ---------- Routing ----------
app.MapControllers();

app.Run();
