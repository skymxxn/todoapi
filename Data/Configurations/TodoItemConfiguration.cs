using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Todo.Api.Entities;

namespace Todo.Api.Data.Configurations;

public class TodoItemConfiguration : IEntityTypeConfiguration<TodoItem>
{
    public void Configure(EntityTypeBuilder<TodoItem> builder)
    {
        builder.HasKey(x => x.Id);
        
        builder.Property(x => x.Name)
            .IsRequired()
            .HasMaxLength(128);
        
        builder.Property(x => x.Description)
            .HasMaxLength(1024);
        
        builder.Property(x => x.IsCompleted)
            .HasDefaultValue(false);
        
        builder.HasOne(x => x.Category)
            .WithMany(x => x.TodoItems)
            .HasForeignKey(x => x.CategoryId)
            .OnDelete(DeleteBehavior.SetNull);

        builder.HasIndex(x => x.Name);
        builder.HasIndex(x => x.CreatedAt);
        builder.HasIndex(x => x.IsCompleted);
        builder.HasIndex(x => x.CategoryId);
    }
}