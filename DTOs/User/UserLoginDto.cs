using System.ComponentModel.DataAnnotations;

namespace Todo.Api.Dtos.User;

public class UserLoginDto
{
    [DataType(DataType.EmailAddress)]
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Email is invalid")]
    public string Email { get; set; } = string.Empty;
    [DataType(DataType.Password)]
    [Required(ErrorMessage = "Password is required")]
    public string Password { get; set; } = string.Empty;
}