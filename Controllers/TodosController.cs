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
    
    [HttpGet]
    public async Task<ActionResult<List<TodoItemDto>>> Get(
        [FromQuery] string sortBy = "CreatedAt", 
        [FromQuery] string sortOrder = "desc", 
        [FromQuery] string? nameFilter = null,
        [FromQuery] bool? isCompleted = null, 
        [FromQuery] int? categoryId = null,
        [FromQuery] DateTime? startDate = null,
        [FromQuery] DateTime? endDate = null,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 25)
    {
        var userId = User.GetUserId();
        var todos = await _todoService
            .GetFilteredAndSortedTodos(
                userId,
                sortBy,
                sortOrder,
                nameFilter,
                isCompleted,
                categoryId,
                startDate,
                endDate,
                page,
                pageSize);
        return Ok(todos.Adapt<List<TodoItemDto>>());
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> GetById(int id)
    {
        var userId = User.GetUserId();
        var result = await _todoService.GetTodoByIdAsync(id, userId);
        return result.ToActionResult();
    }
    
    [HttpPost]
    public async Task<IActionResult> Create(CreateTodoItemDto createDto)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        var userId = User.GetUserId();
        var result = await _todoService.CreateTodoAsync(createDto, userId);
        return result.ToActionResult();
    }
    
    [HttpPut("{id}")]
    public async Task<IActionResult> Update(int id, UpdateTodoItemDto updateDto)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        var userId = User.GetUserId();
        var result = await _todoService.UpdateTodoAsync(id, updateDto, userId);
        return result.ToActionResult();
    }
    
    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(int id)
    {
        var userId = User.GetUserId();
        var result = await _todoService.DeleteTodoAsync(id, userId);
        return result.ToActionResult();
    }
}