namespace AuthWithJwtBearer.Dtos;

public class LoginResponseDto
{
    public string Token { get; set; } = string.Empty;
    public long TokenExpired { get; set; }
    public string RefreshToken { get; set; } = string.Empty;
    public long RefreshTokenExpired { get; set; }
}