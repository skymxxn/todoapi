using System.Security.Claims;
using Mapster;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Todo.Api.Services.Interfaces;
using Todo.Api.Dtos.Todo;
using Todo.Api.Extensions;

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

    private static Guid? GetUserId(ClaimsPrincipal user)
    {
        var userIdClaim = user.FindFirst(ClaimTypes.NameIdentifier);
        if (userIdClaim == null)
        {
            return null;
        }

        if (Guid.TryParse(userIdClaim.Value, out var userId))
        {
            return userId;
        }

        return null;
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
    public async Task<IActionResult> GetById(int id)
    {
        var userId = GetUserId(User);
        if (userId is null) return Unauthorized();

        var result = await _todoService.GetTodoByIdAsync(id, userId.Value);
        
        return result.ToActionResult();
    }
    
    [HttpPost]
    public async Task<IActionResult> Create(CreateTodoItemDto createDto)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);
        
        var userId = GetUserId(User);
        if (userId is null) return Unauthorized();

        var result = await _todoService.CreateTodoAsync(createDto, userId.Value);
        
        return result.ToActionResult();
    }
    
    [HttpPut("{id}")]
    public async Task<IActionResult> Update(int id, UpdateTodoItemDto updateDto)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        var userId = GetUserId(User);
        if (userId is null) return Unauthorized();
        
        var result = await _todoService.UpdateTodoAsync(id, updateDto, userId.Value);
        
        return result.ToActionResult();
    }
    
    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(int id)
    {
        var userId = GetUserId(User);
        if (userId is null) return Unauthorized();
        
        var result = await _todoService.DeleteTodoAsync(id, userId.Value);
        
        return result.ToActionResult();
    }
}