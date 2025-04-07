using AuthWithJwtBearer.Dtos;
using Data.Constants;
using Data.Entities;
using Data.Repositories;
using Microsoft.AspNetCore.Identity;

namespace AuthWithJwtBearer.Services;

public interface IAuthService
{
    Task<UserEntity?> GetUserByLogin(string email, string password);
    Task AddRefreshToken(RefreshTokenEntity refreshTokenModel);
    Task<RefreshTokenEntity?> GetRefreshToken(string refreshToken);
    Task<bool> RegisterUser(RegisterUserDto newUser);
}


public class AuthService(IAuthRepository authRepository) : IAuthService
{
    private readonly PasswordHasher<UserEntity> _passwordHasher = new();

    public async Task<UserEntity?> GetUserByLogin(string email, string password)
    {
        var user = await authRepository.GetUserByLogin(email);
        if (user == null) return null;
        
        var isValidPassword = PasswordManager.ValidateEncryption(password, user.Salt, user.PasswordHash!);
        if (!isValidPassword) return null;
        return user;
    }

    public async Task AddRefreshToken(RefreshTokenEntity refreshTokenEntity)
    {
        await authRepository.RemoveRefreshTokenByUserId(refreshTokenEntity.UserEntityId);
        await authRepository.AddRefreshToken(refreshTokenEntity);
    }

    public Task<RefreshTokenEntity?> GetRefreshToken(string refreshToken)
    {
        return authRepository.GetRefreshToken(refreshToken);
    }

    public async Task<bool> RegisterUser(RegisterUserDto newUser)
    {
        var user = new UserEntity
        {
            Email = newUser.Email,
            UserName = newUser.Username,
            PasswordHash = newUser.Password
        };
        return await authRepository.AddUser(user);
    }
}