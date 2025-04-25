using System.Security.Claims;
using Mapster;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Todo.Api.Services.Interfaces;
using Todo.Api.Dtos.Todo;

namespace Todo.Api.Controllers;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class TodosController : ControllerBase
{
    private readonly ITodoService _todoService;
    
    public TodosController(ITodoService todoService)
    {
        _todoService = todoService;
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
        
        var todos = await _todoService
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

        var result = await _todoService.GetTodoByIdAsync(id, Guid.Parse(userId));
        
        if (!result.Success)
        {
            return BadRequest(result.ErrorMessage);
        }
        
        return Ok(result.Data);
    }
    
    [HttpPost]
    public async Task<ActionResult<TodoItemDto>> Create(CreateTodoItemDto createDto)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);
        
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId is null) return Unauthorized();

        var result = await _todoService.CreateTodoAsync(createDto, Guid.Parse(userId));
        
        if (!result.Success)
        {
            return BadRequest(result.ErrorMessage);
        }
        
        return CreatedAtAction(nameof(GetById), new { id = result.Data.Id }, result.Data);
    }
    
    [HttpPut("{id}")]
    public async Task<ActionResult> Update(int id, UpdateTodoItemDto updateDto)
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId is null) return Unauthorized();
        
        var result = await _todoService.UpdateTodoAsync(id, updateDto, Guid.Parse(userId));
 
        if (!result.Success)
        {
            return BadRequest(result.ErrorMessage);
        }
        return NoContent();
    }
    
    [HttpDelete("{id}")]
    public async Task<ActionResult> Delete(int id)
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId is null) return Unauthorized();
        
        var result = await _todoService.DeleteTodoAsync(id, Guid.Parse(userId));
        
        if (!result.Success)
        {
            return BadRequest(result.ErrorMessage);
        }
        
        return NoContent();
    }
}