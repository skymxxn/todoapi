using Microsoft.EntityFrameworkCore;
using Todo.Api.Entities;

namespace Todo.Api.Data;

public class TodoDbContext(DbContextOptions<TodoDbContext> options) : DbContext(options)
{
    public DbSet<TodoItem> TodoItems => Set<TodoItem>();
    public DbSet<User> Users => Set<User>();
    public DbSet<Category> Categories => Set<Category>();
    public DbSet<PasswordResetToken> PasswordResetTokens => Set<PasswordResetToken>();
}

