using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Todo.Api.Entities;

namespace Todo.Api.Data.Configurations;

public class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.HasKey(x => x.Id);
        
        builder.Property(x => x.Username)
            .IsRequired()
            .HasMaxLength(50);
        
        builder.Property(x => x.Email)
            .IsRequired()
            .HasMaxLength(128);
        
        builder.Property(x => x.IsEmailVerified)
            .HasDefaultValue(false);
        
        builder.Property(x => x.EmailVerificationToken)
            .HasMaxLength(512);
        
        builder.Property(x => x.PasswordHash)
            .IsRequired()
            .HasMaxLength(128);
        
        builder.Property(x => x.Role)
            .HasMaxLength(24);
        
        builder.Property(x => x.RefreshToken)
            .HasMaxLength(512);
        
        builder.HasIndex(x => x.Username)
            .IsUnique();
        
        builder.HasIndex(x => x.Email)
            .IsUnique();
    }
}