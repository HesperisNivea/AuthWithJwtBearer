namespace AuthWithJwtBearer.Constants;

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

    static bool Validate()
    {
        
    }

    static string GenerateSalt()
    {
        
    }
    
    static string Encrypt(string password, string salt)
    {
        
    }

    static bool ValidateEncryption(string password, string salt, string hash)
    {
        
    }
    
}