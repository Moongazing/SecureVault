using Moongazing.SecureVault.Abstracts;
using Moongazing.SecureVault.Models;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Moongazing.SecureVault.Services;

public class SecureVaultService : ISecureVault
{
    private readonly SecureVaultConfig config;

    public SecureVaultService(SecureVaultConfig config)
    {
        this.config = config;
    }

    public async Task<string> EncryptWithAESAsync<T>(T data)
    {
        var jsonData = JsonSerializer.Serialize(data);
        using var aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes(config.AESKey);
        aes.IV = Encoding.UTF8.GetBytes(config.AESIv);

        using var encryptor = aes.CreateEncryptor();
        var inputBytes = Encoding.UTF8.GetBytes(jsonData);
        var encryptedBytes = await Task.Run(() => encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length));

        return Convert.ToBase64String(encryptedBytes);
    }

    public async Task<T> DecryptWithAESAsync<T>(string encryptedData)
    {
        using var aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes(config.AESKey);
        aes.IV = Encoding.UTF8.GetBytes(config.AESIv);

        using var decryptor = aes.CreateDecryptor();
        var encryptedBytes = Convert.FromBase64String(encryptedData);
        var decryptedBytes = await Task.Run(() => decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length));

        var jsonData = Encoding.UTF8.GetString(decryptedBytes);
        return JsonSerializer.Deserialize<T>(jsonData)!;
    }

    public async Task<string> EncryptWithRSAAsync(string data)
    {
        using var rsa = RSA.Create();
        rsa.ImportParameters(config.RSAKey ?? throw new InvalidOperationException("RSA key not configured"));
        var dataBytes = Encoding.UTF8.GetBytes(data);

        var encryptedBytes = await Task.Run(() => rsa.Encrypt(dataBytes, RSAEncryptionPadding.Pkcs1));
        return Convert.ToBase64String(encryptedBytes);
    }

    public async Task<string> DecryptWithRSAAsync(string encryptedData)
    {
        using var rsa = RSA.Create();
        rsa.ImportParameters(config.RSAKey ?? throw new InvalidOperationException("RSA key not configured"));
        var encryptedBytes = Convert.FromBase64String(encryptedData);

        var decryptedBytes = await Task.Run(() => rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.Pkcs1));
        return Encoding.UTF8.GetString(decryptedBytes);
    }

    public string GenerateSaltedHash(string data, string salt)
    {
        var combinedData = Encoding.UTF8.GetBytes(data + salt);
        var hash = SHA256.HashData(combinedData);

        return Convert.ToBase64String(hash);
    }
}