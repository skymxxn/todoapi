using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Todo.Api.Entities;

namespace Todo.Api.Data.Configurations;

public class EmailChangeTokenConfiguration : IEntityTypeConfiguration<EmailChangeToken>
{
    public void Configure(EntityTypeBuilder<EmailChangeToken> builder)
    {
        builder.HasKey(x => x.TokenId);
        
        builder.Property(x => x.Token)
            .IsRequired()
            .HasMaxLength(512);
        
        builder.Property(x => x.NewEmail)
            .IsRequired()
            .HasMaxLength(256);

        builder.Property(x => x.IsUsed)
            .HasDefaultValue(false);
        
        builder.HasOne(x => x.User)
            .WithMany()
            .HasForeignKey(x => x.UserId)
            .OnDelete(DeleteBehavior.SetNull);
    }
}