namespace TodoApi.Dtos;

public class CreateTodoItemDto
{
    public string Name { get; set; } = string.Empty;
    public bool IsCompleted { get; set; } = false;
}