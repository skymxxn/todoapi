using Microsoft.EntityFrameworkCore;
using TodoApi.Entities;

namespace TodoApi.Data;

public class TodoContext(DbContextOptions<TodoContext> options) : DbContext(options)
{
    public DbSet<TodoItem> TodoItems { get; set; }
    public DbSet<User> Users { get; set; }
}

