using System.ComponentModel.DataAnnotations;

namespace Todo.Api.Dtos.Account;

public class ChangeEmailDto
{
    [DataType(DataType.EmailAddress)]
    [Required(ErrorMessage = "New email is required")]
    public string NewEmail { get; set; } = string.Empty;
    
    [DataType(DataType.Password)]
    [Required(ErrorMessage = "Current password is required")]
    public string CurrentPassword { get; set; } = string.Empty;
}