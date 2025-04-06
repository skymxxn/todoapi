namespace TodoApi.Entities;

public class TodoItem
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public bool IsCompleted { get; set; } = false;
    public Guid UserId { get; set; }
}