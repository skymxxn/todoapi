using Microsoft.EntityFrameworkCore;
using TodoApi.Data;
using TodoApi.Entities;

namespace TodoApi.Services
{
    public class TodoItemService(TodoContext context) : ITodoItemService
    {
        public async Task<List<TodoItem>> GetFilteredAndSortedTodos(
            Guid userId, string sortBy, string sortOrder,
            string? nameFilter, bool? isCompleted, int? categoryId,
            DateTime? startDate, DateTime? endDate
            )
        {
            IQueryable<TodoItem> query = context.TodoItems
                .Where(t => t.UserId == userId)
                .Include(t => t.Category);

            if (!string.IsNullOrEmpty(nameFilter))
            {
                query = query.Where(t => t.Name.Contains(nameFilter));
            }

            if (isCompleted.HasValue)
            {
                query = query.Where(t => t.IsCompleted == isCompleted.Value);
            }
            
            if (categoryId.HasValue)
            {
                query = query.Where(t => t.CategoryId == categoryId.Value);
            }
            
            if (startDate.HasValue)
            {
                startDate = DateTime.SpecifyKind(startDate.Value, DateTimeKind.Utc);
                query = query.Where(t => t.CreatedAt >= startDate.Value);
            }

            if (endDate.HasValue)
            {
                endDate = DateTime.SpecifyKind(endDate.Value, DateTimeKind.Utc);
                query = query.Where(t => t.CreatedAt <= endDate.Value);
            }

            switch (sortBy.ToLower())
            {
                case "name":
                    query = sortOrder.ToLower() == "desc" ? query.OrderByDescending(t => t.Name) : query.OrderBy(t => t.Name);
                    break;
                case "createdat":
                    query = sortOrder.ToLower() == "desc" ? query.OrderByDescending(t => t.CreatedAt) : query.OrderBy(t => t.CreatedAt);
                    break;
                default:
                    query = query.OrderBy(t => t.Name);
                    break;
            }

            return await query.ToListAsync();
        }
        
    }
}