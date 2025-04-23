using Mapster;
using Microsoft.EntityFrameworkCore;
using Todo.Api.Data;
using Todo.Api.Dtos.Todo;
using Todo.Api.Entities;
using Todo.Api.Services.Interfaces;

namespace Todo.Api.Services
{
    public class TodoService : ITodoService
    {
        private readonly TodoDbContext _context;

        public TodoService(TodoDbContext context)
        {
            _context = context;
        }
        
        public async Task<List<TodoItem>> GetFilteredAndSortedTodos(
            Guid userId, string sortBy, string sortOrder,
            string? nameFilter, bool? isCompleted, int? categoryId,
            DateTime? startDate, DateTime? endDate
            )
        {
            IQueryable<TodoItem> query = _context.TodoItems
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
        
        public async Task<TodoItemDto?> GetTodoByIdAsync(int id, Guid userId)
        {
            var todoItem = await _context.TodoItems
                .Include(t => t.Category)
                .Where(t => t.UserId == userId && t.Id == id)
                .AsNoTracking()
                .FirstOrDefaultAsync();
        
            return todoItem?.Adapt<TodoItemDto>();
        }

        public async Task<TodoResultDto<TodoItemDto>> CreateTodoAsync(CreateTodoItemDto createDto, Guid userId)
        {
            if (createDto.CategoryId.HasValue)
            {
                var categoryExists = await _context.Categories
                    .AnyAsync(c => c.Id == createDto.CategoryId.Value);
                
                if (!categoryExists) return TodoResultDto<TodoItemDto>.Fail("Category not found.");
            }
            
            var todoItem = createDto.Adapt<TodoItem>();
            todoItem.UserId = userId;
            
            _context.TodoItems.Add(todoItem);
            await _context.SaveChangesAsync();
            
            await _context.Entry(todoItem).Reference(t => t.Category).LoadAsync();
            
            var resultDto = todoItem.Adapt<TodoItemDto>();
            return TodoResultDto<TodoItemDto>.Ok(resultDto);
        }

        public async Task<TodoResultDto<object>> UpdateTodoAsync(int id, UpdateTodoItemDto updateDto, Guid userId)
        {
            var todoItem = await _context.TodoItems.FindAsync(id);
            if (todoItem == null) return TodoResultDto<object>.Fail("Todo not found.");
            
            if (todoItem.UserId != userId) return TodoResultDto<object>.Fail("Access denied.");
            
            if (updateDto.CategoryId.HasValue)
            {
                var categoryExists = await _context.Categories
                    .AnyAsync(c => c.Id == updateDto.CategoryId.Value);
                
                if (!categoryExists) return TodoResultDto<object>.Fail("Category not found.");
            }
            
            updateDto.Adapt(todoItem);
            await _context.SaveChangesAsync();
            
            return TodoResultDto<object>.Ok(null);
        }
        
        public async Task<TodoResultDto<object>> DeleteTodoAsync(int id, Guid userId)
        {
            var todoItem = await _context.TodoItems.FindAsync(id);
            if (todoItem == null) return TodoResultDto<object>.Fail("Todo not found.");
            
            if (todoItem.UserId != userId) return TodoResultDto<object>.Fail("Access denied.");
            
            _context.TodoItems.Remove(todoItem);
            await _context.SaveChangesAsync();
            
            return TodoResultDto<object>.Ok(null);
        }
    }
}