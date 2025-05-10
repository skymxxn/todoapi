using Todo.Api.Dtos.Common;
using Todo.Api.Dtos.Todo;
using Todo.Api.Entities;

namespace Todo.Api.Services.Interfaces;

public interface ITodoService
{
    public Task<ResultDto<TodoItemDto>> GetTodoByIdAsync(int id, Guid userId);
    public Task<List<TodoItem>> GetFilteredAndSortedTodos(Guid userId, string sortBy, string sortOrder, string? nameFilter, bool? isCompleted, int? categoryId, DateTime? startDate, DateTime? endDate, int page, int pageSize);
    public Task<ResultDto<TodoItemDto>> CreateTodoAsync(CreateTodoItemDto todoItemDto, Guid userId);
    public Task<ResultDto<TodoItemDto>> UpdateTodoAsync(int id, UpdateTodoItemDto todoItemDto, Guid userId);
    public Task<ResultDto<TodoItemDto>> DeleteTodoAsync(int id, Guid userId);
}