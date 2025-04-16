using System.Security.Claims;
using Mapster;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TodoApi.Data;
using TodoApi.Dtos;
using TodoApi.Entities;
using TodoApi.Services;

namespace TodoApi.Controllers;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class TodoController : ControllerBase
{
    private readonly TodoContext _context;
    private readonly ITodoItemService _todoItemService;
    public TodoController(TodoContext context, ITodoItemService todoItemService)
    {
        _context = context;
        _todoItemService = todoItemService;
    }
    [HttpGet]
    public async Task<ActionResult<List<TodoItemDto>>> Get(
        [FromQuery] string sortBy = "Name", 
        [FromQuery] string sortOrder = "asc", 
        [FromQuery] string? nameFilter = null,
        [FromQuery] bool? isCompleted = null, 
        [FromQuery] int? categoryId = null,
        [FromQuery] DateTime? startDate = null,
        [FromQuery] DateTime? endDate = null)
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId is null) return Unauthorized();
        
        var todos = await _todoItemService
            .GetFilteredAndSortedTodos(
                Guid.Parse(userId),
                sortBy,
                sortOrder,
                nameFilter,
                isCompleted,
                categoryId,
                startDate,
                endDate);
        return Ok(todos.Adapt<List<TodoItemDto>>());
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<TodoItemDto>> GetById(int id)
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId is null) return Unauthorized();
        
        var todoItem = await _context.TodoItems
            .Include(t => t.Category)
            .Where(t => t.UserId == Guid.Parse(userId) && t.Id == id)
            .FirstOrDefaultAsync();
        
        if (todoItem == null) return NotFound();
        
        return Ok(todoItem.Adapt<TodoItemDto>());
    }
    
    [HttpPost]
    public async Task<ActionResult<TodoItemDto>> Create(CreateTodoItemDto createDto)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);
        
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId is null) return Unauthorized();

        if (createDto.CategoryId.HasValue)
        {
            var categoryExists = await _context.Categories.AnyAsync(c => c.Id == createDto.CategoryId.Value);
            if (!categoryExists) return BadRequest("Category not found.");
        }

        var todoItem = createDto.Adapt<TodoItem>();
        todoItem.UserId = Guid.Parse(userId);
        
        _context.TodoItems.Add(todoItem);
        await _context.SaveChangesAsync();

        return CreatedAtAction(nameof(GetById), new { id = todoItem.Id }, todoItem.Adapt<TodoItemDto>());
    }
    
    [HttpPut("{id}")]
    public async Task<ActionResult> Update(int id, CreateTodoItemDto updateDto)
    {
        var todoItem = await _context.TodoItems.FindAsync(id);
        if (todoItem == null) return NotFound();
        
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId is null) return Unauthorized();
        if (Guid.Parse(userId) != todoItem.UserId) return Forbid();
        
        if (updateDto.CategoryId.HasValue)
        {
            var categoryExists = await _context.Categories.AnyAsync(c => c.Id == updateDto.CategoryId.Value);
            if (!categoryExists) return BadRequest("Category not found.");
        }
        
        updateDto.Adapt(todoItem);
        await _context.SaveChangesAsync();
        return NoContent();
    }
    
    [HttpDelete("{id}")]
    public async Task<ActionResult> Delete(int id)
    {
        var todoItem = await _context.TodoItems.FindAsync(id);
        if (todoItem == null) return NotFound();
        
        _context.TodoItems.Remove(todoItem);
        await _context.SaveChangesAsync();
        return NoContent();
    }
}