using System.ComponentModel.DataAnnotations;

namespace AuthWithJwtBearer.Dtos;

public class RegisterUserDto
{
    public string Username { get; init; } = string.Empty;
    [EmailAddress] 
    public required string Email { get; init; }
    
    [DataType(DataType.Password)]
    [Required]
    [MinLength(3)]
    public required string Password { get; init; }

    [DataType(DataType.Password)]
    [Display(Name = "Confirm Password")]
    [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
    public required string ConfirmPassword { get; init; }
}