using Mapster;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Todo.Api.Data;
using Todo.Api.Dtos.Common;
using Todo.Api.Dtos.Todo;
using Todo.Api.Entities;
using Todo.Api.Services.Interfaces;

namespace Todo.Api.Services
{
    public class TodoService : ITodoService
    {
        private readonly TodoDbContext _context;
        private readonly ILogger<TodoService> _logger;
        private readonly IMemoryCache _cache;

        public TodoService(TodoDbContext context, ILogger<TodoService> logger, IMemoryCache cache)
        {
            _context = context;
            _logger = logger;
            _cache = cache;
        }
        
        private async Task<User?> GetUserAsync(Guid userId)
        {
            return await _context.Users.FirstOrDefaultAsync(u => u.Id == userId);
        }
        
        public async Task<List<TodoItem>?> GetFilteredAndSortedTodos(
            Guid userId, string sortBy, string sortOrder,
            string? nameFilter, bool? isCompleted, int? categoryId,
            DateTime? startDate, DateTime? endDate,
            int page, int pageSize
            )
        {
            if (page < 1)
            {
                _logger.LogWarning("Invalid page number {PageNumber}. Setting to default value 1.", page);
                page = 1;
            }
            
            if (pageSize < 1)
            {
                _logger.LogWarning("Invalid page size {PageSize}. Setting to default value 25.", pageSize);
                pageSize = 25;
            }
            
            const int maxPageSize = 100;
            
            if (pageSize > maxPageSize)
            {
                _logger.LogWarning("Page size {PageSize} exceeds maximum limit of {MaxPageSize}. Setting to maximum.", pageSize, maxPageSize);
                pageSize = maxPageSize;
            }
            
            var cacheKey = $"Todos_{userId}_{sortBy}_{sortOrder}_{nameFilter}_{isCompleted}_{categoryId}_{startDate}_{endDate}_{page}_{pageSize}";
            if (_cache.TryGetValue(cacheKey, out List<TodoItem>? cachedTodos))
            {
                return cachedTodos;
            }

            var user = await GetUserAsync(userId);

            if (user == null)
            {
                _logger.LogWarning("User {Username} not found", userId);
                throw new Exception("User not found");
            }
            
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
                    query = sortOrder.Equals("desc", StringComparison.CurrentCultureIgnoreCase) ? query.OrderByDescending(t => t.Name) : query.OrderBy(t => t.Name);
                    break;
                case "createdat":
                    query = sortOrder.Equals("desc", StringComparison.CurrentCultureIgnoreCase) ? query.OrderByDescending(t => t.CreatedAt) : query.OrderBy(t => t.CreatedAt);
                    break;
                default:
                    query = query.OrderBy(t => t.CreatedAt);
                    break;
            }

            _logger.LogInformation("Fetching todos for user {Username}", user.Username);
            _logger.LogInformation("Sorting todos by {SortBy} in {SortOrder} order", sortBy, sortOrder);

            
            var result = await query
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .AsNoTracking()
                .ToListAsync();
            
            _cache.Set(cacheKey, result, new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5)
            });
            
            return result;
        }
        
        public async Task<ResultDto<TodoItemDto>> GetTodoByIdAsync(int id, Guid userId)
        {
            var user = await GetUserAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("User {Username} not found", userId);
                return ResultDto<TodoItemDto>.Fail("User not found.", 404);
            }
            
            var todoItem = await _context.TodoItems
                .Include(t => t.Category)
                .AsNoTracking()
                .FirstOrDefaultAsync(t => t.Id == id);

            if (todoItem == null)
            {
                _logger.LogWarning("Todo with ID {TodoId} not found for user {Username}.", id, user.Username);
                return ResultDto<TodoItemDto>.Fail("Todo not found.", 404);
            }

            if (todoItem.UserId != userId)
            {
                _logger.LogWarning("User {Username} attempted to access Todo with ID {TodoId} without permission.", user.Username, id);
                return ResultDto<TodoItemDto>.Fail("Access denied.", 403);
            }

            _logger.LogInformation("Todo with ID {TodoId} found for user {Username}", id, user.Username);

            return ResultDto<TodoItemDto>.Ok(
                todoItem.Adapt<TodoItemDto>(), message: "Todo found successfully");
        }
        
        public async Task<ResultDto<TodoItemDto>> CreateTodoAsync(CreateTodoItemDto createDto, Guid userId)
        {
            var user = await GetUserAsync(userId);
            
            if (user is null)
            {
                _logger.LogWarning("User {Username} not found", userId);
                return ResultDto<TodoItemDto>.Fail("User not found.", 404);
            }
            
            if (createDto.CategoryId.HasValue)
            {
                var categoryExists = await _context.Categories
                    .AnyAsync(c => c.Id == createDto.CategoryId.Value);

                if (!categoryExists)
                {
                    _logger.LogWarning("Category with ID {CategoryId} not found.", createDto.CategoryId);
                    return ResultDto<TodoItemDto>.Fail("Category not found.", 404);
                }
            }
            
            var todoItem = createDto.Adapt<TodoItem>();
            todoItem.UserId = userId;
            
            _context.TodoItems.Add(todoItem);
            await _context.SaveChangesAsync();
            
            _cache.Remove($"Todos_{userId}_");
            
            _logger.LogInformation("Todo successfully created with ID {TodoId} by user {Username}", todoItem.Id, user.Username);
            
            await _context.Entry(todoItem).Reference(t => t.Category).LoadAsync();
            
            var resultDto = todoItem.Adapt<TodoItemDto>();
            return ResultDto<TodoItemDto>.Ok(
                resultDto, message: "Todo created successfully", 201);
        }

        public async Task<ResultDto<TodoItemDto>> UpdateTodoAsync(int id, UpdateTodoItemDto updateDto, Guid userId)
        {
            var user = await GetUserAsync(userId);

            if (user is null)
            {
                _logger.LogWarning("User {Username} not found", userId);
                return ResultDto<TodoItemDto>.Fail("User not found.", 404);
            }
            
            var todoItem = await _context.TodoItems.FindAsync(id);
            if (todoItem == null)
            {
                _logger.LogWarning("Todo with ID {TodoId} not found.", id);
                return ResultDto<TodoItemDto>.Fail("Todo not found.", 404);
            }

            if (todoItem.UserId != userId)
            {
                _logger.LogWarning("User {Username} attempted to update Todo with ID {TodoId} without permission.", user.Username, id);
                return ResultDto<TodoItemDto>.Fail("Access denied.", 403);
            }
            
            if (updateDto.CategoryId.HasValue)
            {
                var categoryExists = await _context.Categories
                    .AnyAsync(c => c.Id == updateDto.CategoryId.Value);

                if (!categoryExists)
                {
                    _logger.LogWarning("Category with ID {CategoryId} not found.", updateDto.CategoryId);
                    return ResultDto<TodoItemDto>.Fail("Category not found.", 404);
                }
            }
            
            updateDto.Adapt(todoItem);
            await _context.SaveChangesAsync();
            
            _cache.Remove($"Todos_{userId}_");
            
            _logger.LogInformation("Todo with ID {TodoId} successfully updated by user {Username}.", id, user.Username);
            
            return ResultDto<TodoItemDto>.Ok(message: "Todo updated successfully", 204);
        }
        
        public async Task<ResultDto<TodoItemDto>> DeleteTodoAsync(int id, Guid userId)
        {
            var user = await GetUserAsync(userId);

            if (user is null)
            {
                _logger.LogWarning("User {Username} not found", userId);
                return ResultDto<TodoItemDto>.Fail("User not found.", 404);
            }
            
            var todoItem = await _context.TodoItems.FindAsync(id);
            if (todoItem == null)
            {
                _logger.LogWarning("Todo with ID {TodoId} not found.", id);
                return ResultDto<TodoItemDto>.Fail($"Todo with ID {id} not found.", 404);
            }

            if (todoItem.UserId != userId)
            {
                _logger.LogWarning("User {Username} attempted to update Todo with ID {TodoId} without permission.", user.Username, id);
                return ResultDto<TodoItemDto>.Fail("Access denied.", 403);
            }
            
            _context.TodoItems.Remove(todoItem);
            await _context.SaveChangesAsync();
            
            _cache.Remove($"Todos_{userId}_");
            
            _logger.LogInformation("Todo with ID {TodoId} successfully deleted by user {Username}.", id, user.Username);
            
            return ResultDto<TodoItemDto>.Ok(message: "Todo deleted successfully", 204);
        }
    }
}