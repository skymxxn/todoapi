namespace Todo.Api.Options;

public class FrontendOptions
{
    public const string SectionName = "Frontend";
    public required string VerificationUrl { get; set; }
    public required string ResetPasswordUrl { get; set; }
}