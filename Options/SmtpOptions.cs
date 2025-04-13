namespace TodoApi.Options;

public class SmtpOptions
{
    public const string Smtp = "Smtp";
    public required string Host { get; set; }
    public required int Port { get; set; }
    public required string Email { get; set; }
    public required string Password { get; set; }
}