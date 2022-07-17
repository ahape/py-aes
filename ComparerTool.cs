// You have to compile me first!
using System;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

public class Program
{
    private static byte[] key = Encoding.UTF8.GetBytes("cryptographickey"); // 16 bytes

    private static void Main(string[] args)
    {
        if (args.Length == 0)
            throw new ArgumentException("Need to supply some text to encrypt");
        if (args.Length > 1)
            key = Encoding.UTF8.GetBytes(args[1]);

        string enc = Encrypt(args[0]);
        Console.WriteLine("Encrypted: (as hex) {0}", enc);

        string dec = Decrypt(enc);
        Console.WriteLine("Decrypted: {0}", dec);
    }

    private static AesManaged CreateCipher()
    {
        AesManaged aes = new AesManaged();
        aes.Key = key;
        aes.BlockSize = 128;
        aes.IV = new byte[16]; // Leave uninitialized for now
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.PKCS7;
        return aes;
    }

    private static byte[] HexStringToBytes(string hex)
    {
        byte[] bytes = new byte[hex.Length / 2];
        int i, j;
        for (i = j = 0; j < hex.Length; j += 2, i += 1)
            bytes[i] = Convert.ToByte(hex.Substring(j, 2), 16);
        return bytes;
    }

    private static string BytesToHexString(byte[] bytes)
    {
        return string.Join("", Array.ConvertAll(bytes, b => b.ToString("x").PadLeft(2, '0')));
    }

    private static string Encrypt(string plaintext)
    {
        byte[] input = Encoding.UTF8.GetBytes(plaintext);

        using (AesManaged aes = CreateCipher())
        using (ICryptoTransform enc = aes.CreateEncryptor())
            return BytesToHexString(enc.TransformFinalBlock(input, 0, input.Length));
    }

    private static string Decrypt(string ciphertext)
    {
        byte[] input = HexStringToBytes(ciphertext);

        using (AesManaged aes = CreateCipher())
        using (ICryptoTransform dec = aes.CreateDecryptor())
            return Encoding.UTF8.GetString(dec.TransformFinalBlock(input, 0, input.Length));
    }
}
