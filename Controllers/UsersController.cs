using Mapster;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Todo.Api.Data;
using Todo.Api.Entities;
using Todo.Api.Dtos;

namespace Todo.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UsersController(TodoDbContext dbContext) : Controller
{
    [HttpGet]
    [Authorize(Roles = "Admin")]
    public async Task<ActionResult<List<User>>> GetUsers()
    {
        var users = await dbContext.Users.ToListAsync();
        return Ok(users.Adapt<List<User>>());
    }
}
