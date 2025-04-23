using System.ComponentModel.DataAnnotations;

namespace Todo.Api.Dtos.User;

public class UserRegistrationDto
{
    [Required(ErrorMessage = "Username is required")]
    public string Username { get; set; } = string.Empty;
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Email is invalid")]
    public string Email { get; set; } = string.Empty;
    [Required(ErrorMessage = "Password is required")]
    [DataType(DataType.Password)]
    [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be at least 8 characters long.")]
    public string Password { get; set; } = string.Empty;
    [DataType(DataType.Password)]
    [Compare("Password", ErrorMessage = "Passwords do not match.")]
    public string ConfirmPassword { get; set; } = string.Empty;
}