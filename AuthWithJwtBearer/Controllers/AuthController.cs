using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthWithJwtBearer.Dtos;
using AuthWithJwtBearer.Services;
using Data.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.IdentityModel.Tokens;

namespace AuthWithJwtBearer.Controllers;
[ApiController]
[Route("api/[controller]")]
public class AuthController(IAuthService authService, IConfiguration configuration) : ControllerBase
{
     [HttpPost("login")]
    public async Task<ActionResult<LoginResponseDto>> Login([FromBody] LoginRequestDto loginRequest)
    {
        var user = await authService.GetUserByLogin(loginRequest.Email, loginRequest.Password);
        if (user == null) return Unauthorized();
        var token = GenerateToken(loginRequest.Email, false);
        var refreshToken = GenerateToken(loginRequest.Email, true);

        await authService.AddRefreshToken(new RefreshTokenEntity
        {
            RefreshToken = refreshToken,
            UserEntityId = user.Id
        });

        return Ok(new LoginResponseDto
        {
            Token = token,
            RefreshToken = refreshToken,
            TokenExpired = DateTimeOffset.UtcNow.AddMinutes(30).ToUnixTimeSeconds(),
            RefreshTokenExpired = DateTimeOffset.UtcNow.AddMinutes(24 * 60).ToUnixTimeSeconds()
        });
    }
    
    [HttpPost("refresh")]
    public async Task<ActionResult<LoginResponseDto?>> Refresh(string refreshRequest)
    {
        var refreshToken = await authService.GetRefreshToken(refreshRequest);
        if (refreshToken == null) return BadRequest();

        var newToken = GenerateToken(refreshToken.UserEntity.Email!, false);
        var newRefreshToken = GenerateToken(refreshToken.UserEntity.Email!, true);

        await authService.AddRefreshToken(new RefreshTokenEntity
        {
            RefreshToken = newRefreshToken,
            UserEntityId = refreshToken.UserEntityId
        });

        return Ok(new LoginResponseDto
        {
            Token = newToken,
            RefreshToken = newRefreshToken,
            TokenExpired = DateTimeOffset.UtcNow.AddMinutes(30).ToUnixTimeSeconds(),
            RefreshTokenExpired = DateTimeOffset.UtcNow.AddMinutes(24 * 60).ToUnixTimeSeconds()
        });
    }
    
    [HttpPost("register")]
    public async Task<ActionResult> Register([FromBody] RegisterUserDto? registerUser)
    {
        if (registerUser == null) return BadRequest();

        var result = await authService.RegisterUser(registerUser);

        if (result) return Ok();
        return BadRequest();
    }
    
    private string GenerateToken(string email, bool isRefreshToken)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, email)
        };

        var secret = configuration.GetValue<string>($"Jwt:{(isRefreshToken ? "RefreshTokenSecret" : "Secret")}");
        if (secret == null) throw new Exception("Secret not found");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            "AuthServer",
            "User",
            claims,
            expires: DateTime.UtcNow.AddMinutes(isRefreshToken ? 24 * 60 : 30),
            signingCredentials: creds
        );
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

