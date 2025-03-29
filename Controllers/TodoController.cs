using Mapster;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TodoApi.Data;
using TodoApi.Dtos;
using TodoApi.Entities;

namespace TodoApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class TodoController(TodoContext context) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<List<TodoItemDto>>> Get()
    {
        var todos = await context.TodoItems.ToListAsync();
        return Ok(todos.Adapt<List<TodoItemDto>>());
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<TodoItemDto>> GetById(int id)
    {
        var todoItem = await context.TodoItems.FindAsync(id);
        if (todoItem == null) return NotFound();
        
        return Ok(todoItem.Adapt<TodoItemDto>());
    }
    
    [HttpPost]
    public async Task<ActionResult<TodoItemDto>> Create(CreateTodoItemDto createDto)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        var todoItem = createDto.Adapt<TodoItem>(); 
        context.TodoItems.Add(todoItem);
        await context.SaveChangesAsync();

        return CreatedAtAction(nameof(GetById), new { id = todoItem.Id }, todoItem.Adapt<TodoItemDto>());
    }
    
    [HttpPut("{id}")]
    public async Task<ActionResult> Update(int id, CreateTodoItemDto updateDto)
    {
        var todoItem = await context.TodoItems.FindAsync(id);
        if (todoItem == null) return NotFound();
        
        updateDto.Adapt(todoItem);
        await context.SaveChangesAsync();
        return NoContent();
    }
    
    [HttpDelete("{id}")]
    public async Task<ActionResult> Delete(int id)
    {
        var todoItem = await context.TodoItems.FindAsync(id);
        if (todoItem == null) return NotFound();
        
        context.TodoItems.Remove(todoItem);
        await context.SaveChangesAsync();
        return NoContent();
    }
}