using Data.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Data;

public class AuthWithJwtContext(DbContextOptions<AuthWithJwtContext> options) : IdentityDbContext<UserEntity>(options)
{
    public DbSet<RefreshTokenEntity> RefreshTokens { get; set; }
    
}