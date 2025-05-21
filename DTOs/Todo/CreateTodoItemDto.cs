using System.ComponentModel.DataAnnotations;
using Todo.Api.Enums;

namespace Todo.Api.Dtos.Todo;

public class CreateTodoItemDto
{
    [DataType(DataType.Text)]
    [Required(ErrorMessage = "Name is required")]
    [StringLength(50, MinimumLength = 1)]
    public string Name { get; set; } = string.Empty;
    [DataType(DataType.MultilineText)]
    [StringLength(250)]
    public string Description { get; set; } = string.Empty;
    public PriorityLevel PriorityLevel { get; set; } = PriorityLevel.Medium;
    [DataType(DataType.Date)]
    public DateTime? DueDate { get; set; }
    public bool IsCompleted { get; set; } = false;
    public int? CategoryId { get; set; }
}