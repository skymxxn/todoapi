using Todo.Api.Enums;

namespace Todo.Api.Entities;

public class TodoItem
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public PriorityLevel PriorityLevel { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? DueDate { get; set; }
    public bool IsCompleted { get; set; }
    public Guid UserId { get; set; }
    public int? CategoryId { get; set; }
    public Category? Category { get; set; }
}