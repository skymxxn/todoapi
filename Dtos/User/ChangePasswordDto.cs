using System.ComponentModel.DataAnnotations;

namespace TodoApi.Dtos;

public class ChangePasswordDto
{
    public required string OldPassword { get; set; }
    [DataType(DataType.Password)]
    [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be at least 8 characters long.")]
    public required string NewPassword { get; set; }
}