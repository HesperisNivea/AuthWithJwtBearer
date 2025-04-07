using Data.Constants;
using Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace Data.Repositories;

public interface IAuthRepository
{
    Task<UserEntity?> GetUserByLogin(string username);
    Task RemoveRefreshTokenByUserId(string userId);
    Task AddRefreshToken(RefreshTokenEntity? refreshTokenModel);
    Task<RefreshTokenEntity?> GetRefreshToken(string refreshToken);
    Task<bool> AddUser(UserEntity user);
}

public class AuthRepository(AuthWithJwtContext dbContext)
{
    public Task<UserEntity?> GetUserByLogin(string email)
    {
        return dbContext.Users.AsNoTracking().FirstOrDefaultAsync(n => n.Email == email);
    }

    public async Task RemoveRefreshTokenByUserId(string userId)
    {
        var refreshToken = await dbContext.RefreshTokens.FirstOrDefaultAsync(n => n.UserEntityId == userId);
        if (refreshToken != null)
        {
            dbContext.RemoveRange(refreshToken);
            await dbContext.SaveChangesAsync();
        }
    }

    public async Task AddRefreshToken(RefreshTokenEntity? refreshTokenModel)
    {
        if (refreshTokenModel != null)
        {
            await dbContext.RefreshTokens.AddAsync(refreshTokenModel);
            await dbContext.SaveChangesAsync();
        }
    }

    public async Task<RefreshTokenEntity?> GetRefreshToken(string refreshToken)
    {
        return await dbContext.RefreshTokens.Include(r => r.UserEntity).AsNoTracking()
            .FirstOrDefaultAsync(n => n.RefreshToken == refreshToken);
    }

    public async Task<bool> AddUser(UserEntity user)
    {
        // check if password is valid
        var isValidPassword = PasswordManager.ValidatePasswordAgainstPolicy(user.PasswordHash!);
        if (!isValidPassword) return false;
        
        var userExists = await dbContext.Users.AnyAsync(n => n.Email == user.Email);
        if (userExists) return false;
        // generate salt 
        var salt = PasswordManager.GenerateSalt();
        // encrypt password
        var encryptedPassword = PasswordManager.Encrypt(user.PasswordHash!, salt);
        user.PasswordHash = encryptedPassword;
        
        await dbContext.Users.AddAsync(user);
        await dbContext.SaveChangesAsync();
        return true;
    }
}