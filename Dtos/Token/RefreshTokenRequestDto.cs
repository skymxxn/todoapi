namespace Todo.Api.Dtos.Token;

public class RefreshTokenRequestDto
{
    public Guid UserId { get; set; }
    public required string RefreshToken { get; set; }
}