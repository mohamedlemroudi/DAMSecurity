using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DAMSecurityLib.Crypto
{
    public class AESCrypt
    {
        #region Private attributes

        // Aes class used to encrypt/decrypt data
        private Aes aes;

        #endregion

        #region Public properties

        /// <summary>
        /// Key used to encrypt/decrypt data
        /// </summary>
        public byte[] Key
        {
            get { return aes.Key; }
            set { aes.Key = value; }
        }

        /// <summary>
        /// Initialization Vector (IV) to encrypt/decrypt data
        /// </summary>
        public byte[] IV
        {
            get { return aes.IV; }
            set { aes.IV = value; }
        }

        #endregion

        /// <summary>
        /// Default constructor
        /// Initializes AESCrypt with random key and IV
        /// </summary>
        public AESCrypt()
        {
            aes= Aes.Create();
            aes.GenerateIV();
            aes.GenerateKey();
        }

        /// <summary>
        /// Encrypts text and returns encrypted value
        /// </summary>
        /// <param name="text">Text to encrypt</param>
        /// <returns>byte[] corresponding to encrypted text</returns>
        public byte[] Encrypt(string text)
        {
            ICryptoTransform ct = aes.CreateEncryptor();
            byte[] encryptedData;

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, ct, CryptoStreamMode.Write))
                {
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(text);
                    }
                    encryptedData = ms.ToArray();
                }
            }

            return encryptedData;
        }

        /// <summary>
        /// Decrypts encrypted data to a file in disk
        /// </summary>
        /// <param name="encryptedData">Encrypted data to decrypt</param>
        /// <param name="outFileName">File path to store decrypted data</param>
        public void DecryptToFile(byte[] encryptedData, string outFileName)
        {
            ICryptoTransform decryptor = aes.CreateDecryptor();
            byte[] decryptedData;
            using (MemoryStream ms = new MemoryStream(encryptedData))
            {
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    using (MemoryStream msDecrypt = new MemoryStream())
                    {
                        cs.CopyTo(msDecrypt);
                        decryptedData = msDecrypt.ToArray();
                        File.WriteAllBytes(outFileName, decryptedData);
                    }
                }
            }
        }

    }
}
