using System.ComponentModel.DataAnnotations;

namespace Todo.Api.Dtos.Account;

public class ChangePasswordDto
{
    [DataType(DataType.Password)]
    [Required(ErrorMessage = "Old password is required")]
    public string OldPassword { get; set; } = string.Empty;
    
    [Required(ErrorMessage = "New password is required")]
    [DataType(DataType.Password)]
    [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be at least 8 characters long.")]
    public string NewPassword { get; set; } = string.Empty;
}