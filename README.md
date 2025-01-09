SecureVault Library

SecureVault is a .NET Core library designed for secure data encryption and decryption. It supports AES, RSA, hashing, and salting mechanisms, with additional capabilities for working with JSON and XML data formats. The library is built with support for asynchronous operations and Dependency Injection (DI) for flexible integration.
Features

    AES and RSA Encryption/Decryption
        AES-256 with GCM and CBC modes.
        RSA support for 2048/4096-bit keys.
    Hashing and Salting
        Support for PBKDF2, SHA-256, and SHA-512 algorithms.
    JSON and XML Support
        Encrypt and decrypt data in JSON and XML formats.
    Asynchronous Operations
        Full async/await support for large data encryption and decryption.
    Config-Based Settings
        Easily configure encryption keys and settings via appsettings.json.
    Dependency Injection (DI)
        Seamless integration with DI frameworks for scalable applications.

Getting Started
Installation

    Clone the repository or add the source code to your project.
    Ensure you have .NET 6 or higher installed.

Configuration

Add the following section to your appsettings.json file:

{
  "SecureVault": {
    "AESKey": "1234567890123456", // 16 bytes
    "AESIv": "6543210987654321", // 16 bytes
    "RSAKey": null // RSA Key Configuration (Optional)
  }
}

Usage
Dependency Injection Setup

In Program.cs:

var host = Host.CreateDefaultBuilder(args)
    .ConfigureAppConfiguration(config =>
    {
        config.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);
    })
    .ConfigureServices((context, services) =>
    {
        var config = context.Configuration.GetSection("SecureVault").Get<SecureVaultConfig>();
        services.AddSingleton(config);
        services.AddScoped<ISecureVault, SecureVaultService>();
    })
    .Build();

Example Usage

var service = host.Services.GetRequiredService<ISecureVault>();

var testData = new { Name = "Alice", Age = 25 };

// Encrypt data using AES
var encryptedData = await service.EncryptWithAESAsync(testData);

// Decrypt data using AES
var decryptedData = await service.DecryptWithAESAsync<dynamic>(encryptedData);

Console.WriteLine($"Encrypted: {encryptedData}");
Console.WriteLine($"Decrypted: {decryptedData}");

API Reference
Methods

    Task<string> EncryptWithAESAsync<T>(T data)
        Encrypts data using AES encryption.
    Task<T> DecryptWithAESAsync<T>(string encryptedData)
        Decrypts AES-encrypted data.
    Task<string> EncryptWithRSAAsync(string data)
        Encrypts data using RSA encryption.
    Task<string> DecryptWithRSAAsync(string encryptedData)
        Decrypts RSA-encrypted data.
    string GenerateSaltedHash(string data, string salt)
        Generates a salted hash using SHA-256.

Contributing

Contributions are welcome! Please fork the repository and submit a pull request with detailed explanations of your changes.
License

This project is licensed under the MIT License. See the LICENSE file for details.
Contact

For any questions or feedback, please contact the author at tunahan.ali.ozturk@outlook.com.
