using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace DAMSecurityLib.Crypto
{
    public class RSACrypt
    {
        /// <summary>
        /// Save certificate public key to a file on disk
        /// </summary>
        /// <param name="pfxFilename">Pfx file path to extract public key</param>
        /// <param name="pfxPassword">Pfx password</param>
        /// <param name="publicKeyFile">File path to store certificate public key</param>
        public static void SavePublicKey(string pfxFilename, string pfxPassword, string publicKeyFile)
        {
            X509Certificate2 certificate = new X509Certificate2(pfxFilename, pfxPassword);
            
            RSA? publicKey = certificate.GetRSAPublicKey();
            if (publicKey!=null)
            {
                SavePublicKey(publicKey, publicKeyFile);
            }
        }

        /// <summary>
        /// Load Certificate public key stored in disk
        /// </summary>
        /// <param name="publicKeyFile">Public path file path</param>
        /// <returns>RSA certificate with public key</returns>
        public static RSA LoadPublicKey(string publicKeyFile)
        {
            RSAParameters publicKeyParams = new RSAParameters();
            using (StreamReader reader = new StreamReader(publicKeyFile))
            {
                string? line = reader.ReadLine();
                if (line != null)
                    publicKeyParams.Modulus = Convert.FromBase64String(line);
                line = reader.ReadLine();
                if (line != null)
                    publicKeyParams.Exponent = Convert.FromBase64String(line);
            }

            RSA rsa = RSA.Create();
            rsa.ImportParameters(publicKeyParams);
            return rsa;
        }

        /// <summary>
        /// Save RSA Public key to a file
        /// </summary>
        /// <param name="publicKey">RSA Public key to store in disk</param>
        /// <param name="publicKeyFile">Filesystem file path to store public key</param>
        public static void SavePublicKey(RSA publicKey, string publicKeyFile)
        {
            RSAParameters publickeyParams = publicKey.ExportParameters(false);
            using (StreamWriter writer = new StreamWriter(publicKeyFile))
            {
                byte[]? modulus = publickeyParams.Modulus;
                if (modulus != null)
                    writer.WriteLine(Convert.ToBase64String(modulus));
                byte[]? exponent = publickeyParams.Exponent;
                if (exponent != null)
                    writer.WriteLine(Convert.ToBase64String(exponent));
            }
        }
   
        /// <summary>
        /// Encrypt AESKey with RSA public key
        /// </summary>
        /// <param name="aesKey">AES Key to encrypt</param>
        /// <param name="publicKey">RSA public key to encrypt with</param>
        /// <returns>Encrypted AES key</returns>
        public static byte[] EncryptAESKey(byte[] aesKey, RSAParameters publicKey)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(publicKey);
                byte[] encryptedAesKey = rsa.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);
                return encryptedAesKey;
            }
                
        }

        public static byte[] DecryptAESKeyWithPrivateKey(byte[] encrypteKey, X509Certificate2 certificate)
        {
            using (RSA? rsa = certificate.GetRSAPrivateKey())
            {
                byte[] aesKey;
                if (rsa != null)
                    aesKey = rsa.Decrypt(encrypteKey, RSAEncryptionPadding.OaepSHA256);
                else
                    aesKey = new byte[0];
                return aesKey;

            }
            
        }
    }
}
