using TodoApi.Dtos;
using TodoApi.Entities;

namespace TodoApi.Services;

public interface ITodoItemService
{
    Task<List<TodoItem>> GetFilteredAndSortedTodos(Guid userId, string sortBy, string sortOrder, string? nameFilter, bool? isCompleted, int? categoryId, DateTime? startDate, DateTime? endDate);
}