namespace Todo.Api.Options;

public class AppSettingsOptions
{
    public const string SectionName = "AppSettings";
    public required string Issuer { get; set; }
    public required string Audience { get; set; }
    
    public required string AccessTokenKey { get; set; }
    public required int AccessTokenExpirationInMinutes { get; set; }
    
    public required string EmailVerificationTokenKey { get; set; }
    public required int EmailVerificationTokenExpirationInMinutes { get; set; }
    
    public required string EmailChangeTokenKey { get; set; }
    public required int EmailChangeTokenExpirationInMinutes { get; set; }
    
    public required string PasswordResetTokenKey { get; set; }
    public required int PasswordResetTokenExpirationInMinutes { get; set; }
}