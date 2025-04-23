using System.ComponentModel.DataAnnotations;

namespace Todo.Api.Dtos.Todo;

public class UpdateTodoItemDto
{
    [Required]
    [StringLength(50, MinimumLength = 1)]
    public string Name { get; set; } = string.Empty;
    [DataType(DataType.MultilineText)]
    [StringLength(250)]
    public string Description { get; set; } = string.Empty;
    public bool IsCompleted { get; set; } = false;
    public int? CategoryId { get; set; }
}