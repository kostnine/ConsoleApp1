using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AES_Encryption
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("AES Encryption System");
            Console.WriteLine("Choose an option:");
            Console.WriteLine("1. Encrypt text and save to file");
            Console.WriteLine("2. Decrypt text from file");
            string option = Console.ReadLine();

            switch (option)
            {
                case "1":
                    EncryptText();
                    break;
                case "2":
                    DecryptTextFromFile();
                    break;
                default:
                    Console.WriteLine("Invalid option.");
                    break;
            }
        }

        static void EncryptText()
        {
            Console.WriteLine("Enter text to encrypt:");
            string inputText = Console.ReadLine();

            Console.WriteLine("Enter password:");
            string password = Console.ReadLine();

            Console.WriteLine("Select encryption mode: 1. ECB, 2. CBC, 3. CFB");
            CipherMode mode = ChooseCipherMode(Console.ReadLine());

            byte[] encryptedBytes = EncryptString(inputText, password, mode);

            Console.WriteLine($"Encrypted text: {Convert.ToBase64String(encryptedBytes)}");
            File.WriteAllBytes("encryptedText.aes", encryptedBytes);
            Console.WriteLine("Text has been encrypted and saved to file.");
        }

        static void DecryptTextFromFile()
        {
            Console.WriteLine("Enter password for decryption:");
            string password = Console.ReadLine();

            Console.WriteLine("Select decryption mode: 1. ECB, 2. CBC, 3. CFB");
            CipherMode mode = ChooseCipherMode(Console.ReadLine());

            byte[] encryptedBytes = File.ReadAllBytes("encryptedText.aes");
            string decryptedText = DecryptString(encryptedBytes, password, mode);

            Console.WriteLine($"Decrypted text: {decryptedText}");
        }

        static CipherMode ChooseCipherMode(string choice)
        {
            switch (choice)
            {
                case "1":
                    return CipherMode.ECB;
                case "2":
                    return CipherMode.CBC;
                case "3":
                    return CipherMode.CFB;
                default:
                    Console.WriteLine("Invalid mode selected. Defaulting to CBC.");
                    return CipherMode.CBC;
            }
        }

        static byte[] EncryptString(string inputText, string password, CipherMode mode)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Mode = mode;
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                aesAlg.Key = pdb.GetBytes(32);
                aesAlg.IV = pdb.GetBytes(16);

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(inputText);
                        }
                        return msEncrypt.ToArray();
                    }
                }
            }
        }

        static string DecryptString(byte[] cipherText, string password, CipherMode mode)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Mode = mode;
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                aesAlg.Key = pdb.GetBytes(32);
                aesAlg.IV = pdb.GetBytes(16);

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
}

