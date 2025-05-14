namespace Todo.Api.Dtos.Token;

public class TokenResponseDto
{
    public required string AccessToken { get; set; }
    public required string RefreshToken { get; set; }
}