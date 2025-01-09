namespace Moongazing.SecureVault.Abstracts;

public interface ISecureVault
{
    Task<string> EncryptWithAESAsync<T>(T data);
    Task<T> DecryptWithAESAsync<T>(string encryptedData);
    Task<string> EncryptWithRSAAsync(string data);
    Task<string> DecryptWithRSAAsync(string encryptedData);
    string GenerateSaltedHash(string data, string salt);
}