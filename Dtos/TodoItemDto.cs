namespace TodoApi.Dtos;

public class TodoItemDto()
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public bool IsCompleted { get; set; } = false;
}