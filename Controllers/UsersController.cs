using Mapster;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TodoApi.Data;
using TodoApi.Dtos;
using TodoApi.Entities;

namespace TodoApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UsersController(TodoContext context) : Controller
{
    [HttpGet]
    [Authorize(Roles = "Admin")]
    public async Task<ActionResult<List<User>>> GetUsers()
    {
        var users = await context.Users.ToListAsync();
        return Ok(users.Adapt<List<User>>());
    }
}