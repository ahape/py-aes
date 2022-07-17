using System;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

class Program
{
    static byte[] key = Encoding.UTF8.GetBytes("cryptographickey"); // 16 bytes
    static void Main(string[] args)
    {
        if (args.Length == 0)
            throw new ArgumentException("Need to supply some text to encrypt");

        var enc = Encrypt(args[0]);
        Console.WriteLine(enc);
        var dec = Decrypt(enc);
        Console.WriteLine(dec);
    }

    static AesManaged CreateCipher()
    {
        var aes = new AesManaged();
        aes.Key = key;
        aes.BlockSize = 128;
        aes.IV = new byte[16]; // Leave uninitialized for now
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.PKCS7;
        return aes;
    }

    static byte[] HexStringToBytes(string hex)
    {
        byte[] bytes = new byte[hex.Length / 2];
        int i, j;
        for (i = j = 0; j < hex.Length; j += 2, i += 1)
            bytes[i] = Convert.ToByte(hex.Substring(j, 2), 16);
        return bytes;
    }

    static string BytesToHexString(byte[] bytes)
    {
        return string.Join("", Array.ConvertAll(bytes, b => b.ToString("x").PadLeft(2, '0')));
    }

    static string Encrypt(string plaintext)
    {
        var input = Encoding.UTF8.GetBytes(plaintext);

        using (var aes = CreateCipher())
        using (var enc = aes.CreateEncryptor())
            return BytesToHexString(enc.TransformFinalBlock(input, 0, input.Length));
    }

    static string Decrypt(string ciphertext)
    {
        var input = HexStringToBytes(ciphertext);

        using (var aes = CreateCipher())
        using (var dec = aes.CreateDecryptor())
            return Encoding.UTF8.GetString(dec.TransformFinalBlock(input, 0, input.Length));
    }
}
