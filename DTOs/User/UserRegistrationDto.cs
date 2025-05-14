using System.ComponentModel.DataAnnotations;

namespace Todo.Api.Dtos.User;

public class UserRegistrationDto
{
    [Required(ErrorMessage = "Username is required")]
    [DataType(DataType.Text)]
    [StringLength(100, MinimumLength = 4, ErrorMessage = "Username must be at least 4 characters long.")]
    [RegularExpression("^(?!\\d)[a-zA-Z0-9_.]+$", ErrorMessage = "Username must start with a letter and contain only letters, numbers, underscores, and dots.")]
    public string Username { get; set; } = string.Empty;
    [Required(ErrorMessage = "Email is required")]
    [DataType(DataType.EmailAddress)]
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