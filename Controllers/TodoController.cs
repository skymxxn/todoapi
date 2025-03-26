using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TodoApi.Data;

namespace TodoApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class TodoController : ControllerBase
{
    private readonly TodoContext _context;
    public TodoController(TodoContext context)
    {
        _context = context;
    }

    [HttpGet]
    public async Task<ActionResult<List<TodoItem>>> Get()
    {
        var todos = await _context.TodoItems.ToListAsync();
        return Ok(todos);
    }

    [HttpGet("{id}")]
    public async Task<ActionResult> GetById(int id)
    {
        return await _context.TodoItems.FindAsync(id) switch
        {
            TodoItem todoItem => Ok(todoItem),
            null => NotFound(),
        };
    }
    
    [HttpPost]
    public async Task<ActionResult> Post(TodoItem todoItem)
    {
        if (ModelState.IsValid)
        { 
            _context.TodoItems.Add(todoItem);
            await _context.SaveChangesAsync();
            return CreatedAtAction(nameof(GetById), new { id = todoItem.Id }, todoItem);
        }
        return BadRequest(ModelState);
    }
    
    [HttpPut("{id}")]
    public async Task<ActionResult> Update(int id, TodoItem todoItem)
    {
        if (id != todoItem.Id)
        {
            return BadRequest();
        }
        _context.Entry(todoItem).State = EntityState.Modified;
        try
        {
            await _context.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException)
        {
            if (!await _context.TodoItems.AnyAsync(t => t.Id == id))
            {
                return NotFound();
            }
            throw;
        }
        return NoContent();
    }
    
    [HttpDelete("{id}")]
    public async Task<ActionResult> Delete(int id)
    {
        var todoItem = await _context.TodoItems.FindAsync(id);
        if (todoItem == null)
        {
            return NotFound();
        }
        _context.TodoItems.Remove(todoItem);
        await _context.SaveChangesAsync();
        return NoContent();
    }
}