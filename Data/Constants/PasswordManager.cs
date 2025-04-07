using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace Data.Constants;

public static class PasswordManager
{
    private static int MinimumLengthPassword { get; }
    private static int MaximumLengthPassword { get; }
    private static int MinimumLowerCaseChars { get; }
    private static int MinimumUpperCaseChars { get; }
    private static int MinimumNumericChars { get; }
    private static int MinimumSpecialChars { get; }

    static PasswordManager()
    {
        MinimumLengthPassword = 12;
        MaximumLengthPassword = 128;
        MinimumLowerCaseChars = 2;
        MinimumUpperCaseChars = 2;
        MinimumNumericChars = 2;
        MinimumSpecialChars = 2;
    }

    public static string GenerateSalt()
    {
        var randomBytes = new byte[128 / 8];
        using var generator = RandomNumberGenerator.Create();

        generator.GetBytes(randomBytes);
        return Convert.ToBase64String(randomBytes);
    }
    
    public static string Encrypt(string value, string salt)
    {
        var valueBytes = KeyDerivation.Pbkdf2(
            password: value,
            salt: Encoding.UTF8.GetBytes(salt),
            prf: KeyDerivationPrf.HMACSHA512,
            iterationCount: 10000,
            numBytesRequested: 256 / 8);

        return Convert.ToBase64String(valueBytes);
    }

    public static bool ValidateEncryption(string password, string salt, string hash)
    {
        var encryptedPassword = Encrypt(password, salt);
        if(hash != encryptedPassword)
            return false;
        
        return true;
    }
    
}