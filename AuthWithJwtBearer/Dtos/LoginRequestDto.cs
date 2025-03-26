﻿using System.ComponentModel.DataAnnotations;

namespace AuthWithJwtBearer.Dtos;

public class LoginRequestDto
{
    [Required] public string Email { get; set; } = string.Empty;

    [Required] public string Password { get; set; } = string.Empty;
}