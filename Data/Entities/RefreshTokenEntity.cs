namespace Data.Entities;

public class RefreshTokenEntity
{
    public int Id { get; set; }
    public string UserEntityId { get; set; } = string.Empty;
    public virtual UserEntity UserEntity { get; set; } = null!;
    public string RefreshToken { get; set; } = string.Empty;
    
}