using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace Netcorext.Extensions.Hash;

public static class HashExtension
{
    public static string HmacMd5HashCode(this string value, string key, Encoding encoding = default)
    {
        return HmacMd5Hash(value, key, encoding).ToHex();
    }

    public static string HmacMd5HashCode(this byte[] value, byte[] key)
    {
        return HmacMd5Hash(value, key).ToHex();
    }

    public static byte[] HmacMd5Hash(this string value, string key, Encoding encoding = default)
    {
        if (encoding == null) encoding = Encoding.UTF8;

        return new HMACMD5(encoding.GetBytes(key)).ComputeHash(encoding.GetBytes(value));
    }

    public static byte[] HmacMd5Hash(this byte[] value, byte[] key)
    {
        return new HMACMD5(key).ComputeHash(value);
    }

    public static string HmacSha1HashCode(this string value, string key, Encoding encoding = default)
    {
        return HmacSha1Hash(value, key, encoding).ToHex();
    }

    public static string HmacSha1HashCode(this byte[] value, byte[] key)
    {
        return HmacSha1Hash(value, key).ToHex();
    }

    public static byte[] HmacSha1Hash(this string value, string key, Encoding encoding = default)
    {
        if (encoding == null) encoding = Encoding.UTF8;

        return new HMACSHA1(encoding.GetBytes(key)).ComputeHash(encoding.GetBytes(value));
    }

    public static byte[] HmacSha1Hash(this byte[] value, byte[] key)
    {
        return new HMACSHA1(key).ComputeHash(value);
    }

    public static string HmacSha256HashCode(this string value, string key, Encoding encoding = default)
    {
        return HmacSha256Hash(value, key, encoding).ToHex();
    }

    public static string HmacSha256HashCode(this byte[] value, byte[] key)
    {
        return HmacSha256Hash(value, key).ToHex();
    }

    public static byte[] HmacSha256Hash(this string value, string key, Encoding encoding = default)
    {
        if (encoding == null) encoding = Encoding.UTF8;

        return new HMACSHA256(encoding.GetBytes(key)).ComputeHash(encoding.GetBytes(value));
    }

    public static byte[] HmacSha256Hash(this byte[] value, byte[] key)
    {
        return new HMACSHA256(key).ComputeHash(value);
    }

    public static string Md5HashCode(this string value, Encoding encoding = default)
    {
        return Md5Hash(value, encoding).ToHex();
    }

    public static string Md5HashCode(this Stream value)
    {
        return Md5Hash(value).ToHex();
    }

    public static string Md5HashCode(this byte[] value)
    {
        return Md5Hash(value).ToHex();
    }

    public static byte[] Md5Hash(this string value, Encoding encoding = default)
    {
        if (encoding == null) encoding = Encoding.UTF8;

        return MD5.Create().ComputeHash(encoding.GetBytes(value));
    }

    public static byte[] Md5Hash(this Stream value)
    {
        return MD5.Create().ComputeHash(value);
    }

    public static byte[] Md5Hash(this byte[] value)
    {
        return MD5.Create().ComputeHash(value);
    }

    public static string Sha1HashCode(this string value, Encoding encoding = default)
    {
        return Sha1Hash(value, encoding).ToHex();
    }

    public static string Sha1HashCode(this Stream value)
    {
        return Sha1Hash(value).ToHex();
    }

    public static string Sha1HashCode(this byte[] value)
    {
        return Sha1Hash(value).ToHex();
    }

    public static byte[] Sha1Hash(this string value, Encoding encoding = default)
    {
        if (encoding == null) encoding = Encoding.UTF8;

        return SHA1.Create().ComputeHash(encoding.GetBytes(value));
    }

    public static byte[] Sha1Hash(this Stream value)
    {
        return SHA1.Create().ComputeHash(value);
    }

    public static byte[] Sha1Hash(this byte[] value)
    {
        return SHA1.Create().ComputeHash(value);
    }

    public static string Sha256HashCode(this string value, Encoding encoding = default)
    {
        return Sha256Hash(value, encoding).ToHex();
    }

    public static string Sha256HashCode(this Stream value)
    {
        return Sha256Hash(value).ToHex();
    }

    public static string Sha256HashCode(this byte[] value)
    {
        return Sha256Hash(value).ToHex();
    }

    public static byte[] Sha256Hash(this string value, Encoding encoding = default)
    {
        if (encoding == null) encoding = Encoding.UTF8;

        return SHA256.Create().ComputeHash(encoding.GetBytes(value));
    }

    public static byte[] Sha256Hash(this Stream value)
    {
        return SHA256.Create().ComputeHash(value);
    }

    public static byte[] Sha256Hash(this byte[] value)
    {
        return SHA256.Create().ComputeHash(value);
    }

    public static string Pbkdf2HashCode(this string password)
    {
        return Pbkdf2Hash(password).ToHex();
    }

    public static string Pbkdf2HashCode(this string password, long unixTimeMilliseconds)
    {
        return Pbkdf2Hash(password, unixTimeMilliseconds).ToHex();
    }

    public static byte[] Pbkdf2Hash(this string password)
    {
        return Pbkdf2Hash(password, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
    }

    public static byte[] Pbkdf2Hash(this string password, long unixTimeMilliseconds, KeyDerivationPrf prf = KeyDerivationPrf.HMACSHA1)
    {
        var salt = BitConverter.GetBytes(unixTimeMilliseconds);

        var hash = KeyDerivation.Pbkdf2(password,
                                        salt,
                                        prf,
                                        10000,
                                        256 / 8);

        return hash;
    }


    private static string ToHex(this byte[] bytes, bool uppercase = true)
    {
        if (bytes == null)
            throw new ArgumentNullException(nameof(bytes));

        return uppercase
                   ? BitConverter.ToString(bytes).Replace("-", string.Empty)
                   : BitConverter.ToString(bytes).Replace("-", string.Empty).ToLower();
    }
}