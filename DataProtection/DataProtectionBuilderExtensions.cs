using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using System;
using System.Xml.Linq;
using Newtonsoft.Json;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace Microsoft.AspNetCore.DataProtection
{
    /// <summary>
    /// Extensions for configuring data protection using an <see cref="IDataProtectionBuilder"/>.
    /// </summary>
    public static class DataProtectionBuilderExtensions
    {
        /// <summary>
        /// Configures keys to be encrypted with AES before being persisted to
        /// storage.
        /// </summary>
        /// <param name="builder">The <see cref="IDataProtectionBuilder"/>.</param>
        /// use on the local machine, 'false' if the key should only be decryptable by the current
        /// Windows user account.</param>
        /// <returns>A reference to the <see cref="IDataProtectionBuilder" /> after this operation has completed.</returns>
        /// <remarks>
        /// This API is only supported on Windows platforms.
        /// </remarks>
        public static IDataProtectionBuilder ProtectKeysWithAES(this IDataProtectionBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            builder.Services.AddSingleton<IConfigureOptions<KeyManagementOptions>>(services =>
            {
                var loggerFactory = services.GetService<ILoggerFactory>() ?? NullLoggerFactory.Instance;
                return new ConfigureOptions<KeyManagementOptions>(options =>
                {
                    options.XmlEncryptor = new AesXmlEncryptor();
                });
            });

            return builder;
        }
    }
    /// <summary>
    /// An <see cref="IXmlEncryptor"/> that encrypts XML elements with a Aes encryptor.
    /// </summary>
    sealed class AesXmlEncryptor : IXmlEncryptor
    {
        /// <summary>
        /// Encrypts the specified <see cref="XElement"/> with a null encryptor, i.e.,
        /// by returning the original value of <paramref name="plaintextElement"/> unencrypted.
        /// </summary>
        /// <param name="plaintextElement">The plaintext to echo back.</param>
        /// <returns>
        /// An <see cref="EncryptedXmlInfo"/> that contains the null-encrypted value of
        /// <paramref name="plaintextElement"/> along with information about how to
        /// decrypt it.
        /// </returns>
        public EncryptedXmlInfo Encrypt(XElement plaintextElement)
        {
            if (plaintextElement == null)
            {
                throw new ArgumentNullException(nameof(plaintextElement));
            }
            // <encryptedKey>
            //   <!-- This key is encrypted with {provider}. -->
            //   <value>{base64}</value>
            // </encryptedKey>

            var Jsonxmlstr =JsonConvert.SerializeObject(plaintextElement);
            var EncryptedData = EncryptHelper.AESEncrypt(Jsonxmlstr, "b587be32-0420-4eb1-89c6-01bb999e18fe");
            var newElement = new XElement("encryptedKey",
                new XComment(" This key is encrypted with AES."),
                new XElement("value",EncryptedData));

            return new EncryptedXmlInfo(newElement, typeof(AesXmlDecryptor));
        }
    }
    /// <summary>
    /// An <see cref="IXmlDecryptor"/> that decrypts XML elements with a Aes decryptor.
    /// </summary>
    sealed class AesXmlDecryptor : IXmlDecryptor
    {
        /// <summary>
        /// Decrypts the specified XML element.
        /// </summary>
        /// <param name="encryptedElement">An encrypted XML element.</param>
        /// <returns>The decrypted form of <paramref name="encryptedElement"/>.</returns>
        public XElement Decrypt(XElement encryptedElement)
        {
            if (encryptedElement == null)
            {
                throw new ArgumentNullException(nameof(encryptedElement));
            }

            // <encryptedKey>
            //   <!-- This key is encrypted with {provider}. -->
            //   <value>{base64}</value>
            // </encryptedKey>
            var EncryptedData=(string)encryptedElement.Element("value");
            var Jsonxmlstr = EncryptHelper.AESDecrypt(EncryptedData, "b587be32-0420-4eb1-89c6-01bb999e18fe");

            // Return a clone of the single child node.
            return JsonConvert.DeserializeObject<XElement>(Jsonxmlstr);
        }
    }
    #region AES
    public class EncryptHelper
    {
        static readonly byte[] AES_IV = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };
        /// <summary>
        /// AES加密算法
        /// </summary>
        /// <param name="encryptString">加密前字符串</param>
        /// <param name="keytype">秘钥</param>
        /// <returns></returns>
        public static string AESEncrypt(string encryptString, string encryptKey)
        {
            if (string.IsNullOrWhiteSpace(encryptString)) return null;
            if (string.IsNullOrWhiteSpace(encryptKey)) return null;
            encryptKey = encryptKey.PadRight(32, ' ');
            byte[] keyBytes = Encoding.UTF8.GetBytes(encryptKey.Substring(0, 32));
            using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
            {
                aesAlg.Key = keyBytes;
                aesAlg.IV = AES_IV;
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(encryptString);
                        }
                        byte[] bytes = msEncrypt.ToArray();
                        return Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_');
                    }
                }
            }
        }
        /// <summary>
        /// AES解密算法
        /// </summary>
        /// <param name="decryptString">解密前的字符串</param>
        /// <param name="keytype">秘钥</param>
        /// <returns></returns>
        public static string AESDecrypt(string decryptString, string decryptKey)
        {
            if (string.IsNullOrWhiteSpace(decryptString)) return null;
            decryptString = decryptString.Replace('-', '+').Replace('_', '/');
            if (string.IsNullOrWhiteSpace(decryptKey)) return null;
            decryptKey = decryptKey.PadRight(32, ' ');
            byte[] keyBytes = Encoding.UTF8.GetBytes(decryptKey.Substring(0, 32));
            Byte[] inputBytes = Convert.FromBase64String(decryptString);
            using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
            {
                aesAlg.Key = keyBytes;
                aesAlg.IV = AES_IV;
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream(inputBytes))
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srEncrypt = new StreamReader(csEncrypt))
                        {
                            return srEncrypt.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
    #endregion
}
