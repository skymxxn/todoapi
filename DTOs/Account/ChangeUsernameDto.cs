using System.ComponentModel.DataAnnotations;

namespace Todo.Api.Dtos.Account;

public class ChangeUsernameDto
{
    [DataType(DataType.Text)]
    [Required(ErrorMessage = "New username is required")]
    [StringLength(100, MinimumLength = 4, ErrorMessage = "Username must be at least 4 characters long.")]
    [RegularExpression("^(?!\\d)[a-zA-Z0-9_.]+$", ErrorMessage = "Username must start with a letter and contain only letters, numbers, underscores, and dots.")]
    public string NewUsername { get; set; } = string.Empty;
    
    [DataType(DataType.Password)]
    [Required(ErrorMessage = "Current password is required")]
    public string CurrentPassword { get; set; } = string.Empty;
}