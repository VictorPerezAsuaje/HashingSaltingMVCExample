using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace HashingSaltingMVCExample.Services;
public class Crypto
{
    public static byte[] GenerateSalt()
    {
        byte[] salt = new byte[128 / 8];

        using (var rdnGen = RandomNumberGenerator.Create())
        {
                rdnGen.GetNonZeroBytes(salt);
        }

        return salt;
    }

    public static Tuple<string, string> HashPassword(string password, string? salt = null)
    {
        byte[] byteSalt = string.IsNullOrEmpty(salt) ? GenerateSalt() : Convert.FromBase64String(salt);

        string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            password: password,
            salt: byteSalt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 100000,
            numBytesRequested: 256 / 8
        ));

        return Tuple.Create(hashed, Convert.ToBase64String(byteSalt));
    }
}

