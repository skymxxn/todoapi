using Todo.Api.Dtos;
using Todo.Api.Dtos.Todo;
using Todo.Api.Entities;

namespace Todo.Api.Services.Interfaces;

public interface ITodoService
{
    public Task<TodoResultDto<TodoItemDto>> GetTodoByIdAsync(int id, Guid userId);
    public Task<List<TodoItem>> GetFilteredAndSortedTodos(Guid userId, string sortBy, string sortOrder, string? nameFilter, bool? isCompleted, int? categoryId, DateTime? startDate, DateTime? endDate);
    public Task<TodoResultDto<TodoItemDto>> CreateTodoAsync(CreateTodoItemDto todoItemDto, Guid userId);
    public Task<TodoResultDto<TodoItemDto>> UpdateTodoAsync(int id, UpdateTodoItemDto todoItemDto, Guid userId);
    public Task<TodoResultDto<TodoItemDto>> DeleteTodoAsync(int id, Guid userId);
}