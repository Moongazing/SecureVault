using System.Security.Cryptography;

namespace Moongazing.SecureVault.Models
{
    public class SecureVaultConfig
    {
        public string AESKey { get; set; } = string.Empty;
        public string AESIv { get; set; } = string.Empty;
        public RSAParameters? RSAKey { get; set; }
    }
}