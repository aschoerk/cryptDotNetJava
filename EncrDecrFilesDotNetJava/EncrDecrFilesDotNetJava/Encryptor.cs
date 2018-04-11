using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EncrDecrDotNetJava
{
    class AsymmetricEncryptor
    {

        public byte[] EncryptAssymetricByPublic(byte[] toEncrypt, String xmlPublic)
        {
            //Encode with public key
            RSACryptoServiceProvider rsaPublic = new RSACryptoServiceProvider();
            rsaPublic.FromXmlString(xmlPublic);

           
            SymmetricKey symmetricKey = GenerateSymmetricKey();
            byte[] encryptedKey = rsaPublic.Encrypt(symmetricKey.toByteArray(), false);

            byte[] encrypted = EncryptSymmetric(toEncrypt, symmetricKey);

            byte[] combined = new byte[2 + encryptedKey.Length + encrypted.Length];

            combined[0] = (byte)(encryptedKey.Length & 0x00FF);
            combined[1] = (byte)(encryptedKey.Length >> 8);


            for (int i = 0; i < encryptedKey.Length; i++)
            {
                combined[2 + i] = encryptedKey[i];
            }
            for (int i = 0; i < encrypted.Length; i++)
            {
                combined[2 + i + encryptedKey.Length] = encrypted[i];
            }
            return combined;
        }

        public byte[] DecryptTestWise(byte[] toDecrypt, string xmlPrivate)
        {
          
            //Encode with public key
            RSACryptoServiceProvider rsaPrivate = new RSACryptoServiceProvider();
            rsaPrivate.FromXmlString(xmlPrivate);

            int len = toDecrypt[0] + toDecrypt[1] * 256;
            byte[] encryptedSymmetricKey = new byte[len];
            for (int i = 0; i < len; i++)
            {
                encryptedSymmetricKey[i] = toDecrypt[i + 2];
            }

            byte[] encryptedData = new byte[toDecrypt.Length - 2 - len];
            for (int i = 0; i < encryptedData.Length; i++)
            {
                encryptedData[i] = toDecrypt[i + 2 + len];
            }

            byte[] decryptedKey = rsaPrivate.Decrypt(encryptedSymmetricKey, false);


            SymmetricKey s = new SymmetricKey();
            s.fromByteArray(decryptedKey);

            return DecryptTestwise(encryptedData, s);

        }

        /// <summary>
        /// Encrypts the specified data.
        /// </summary>
        /// <param name="data">The data to encrypt</param>
        /// <param name="key">The key to encrypt data.</param>
        /// <returns>
        /// The data encrypted.
        /// </returns>
        private byte[] EncryptSymmetric(byte[] data, SymmetricKey key)
        {
            if (data == null || data.Length == 0)
            {
                throw new ArgumentNullException("data");
            }

            if (key == null)
            {
                throw new ArgumentNullException("key");
            }


            using (AesCryptoServiceProvider providerInLine = new AesCryptoServiceProvider())
            {
                using (MemoryStream stream = new MemoryStream())
                {
                    using (ICryptoTransform cryptoEncryptor = providerInLine.CreateEncryptor(key.Key, key.IV))
                    {
                        using (CryptoStream writerStream = new CryptoStream(stream, cryptoEncryptor, CryptoStreamMode.Write))
                        {
                            writerStream.Write(data, 0, data.Length);
                            writerStream.FlushFinalBlock();                           
                            byte[] res = stream.ToArray();
                            return res;
                        }
                    }
                }
            }

        }

        /// <summary>
        /// Decrypts the specified data.
        /// </summary>
        /// <param name="data">The data to decrypt</param>
        /// <param name="key">The key to decrypt data.</param>
        /// <returns>
        /// The data encrypted.
        /// </returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2202:Do not dispose objects multiple times")]
        public byte[] DecryptTestwise(byte[] data, SymmetricKey key)
        {
            if (data == null || data.Length == 0)
            {
                throw new ArgumentNullException("data");
            }

            if (key == null)
            {
                throw new ArgumentNullException("key");
            }


            using (AesCryptoServiceProvider provider = new AesCryptoServiceProvider())
            {
                using (MemoryStream outputStream = new MemoryStream())
                {
                    using (MemoryStream memStreamEncryptData = new MemoryStream(data))
                    {
                        using (ICryptoTransform cryptoDecryptor = provider.CreateDecryptor(key.Key, key.IV))
                        {
                            using (CryptoStream stream = new CryptoStream(memStreamEncryptData, cryptoDecryptor, CryptoStreamMode.Read))
                            {
                                byte[] resultBuffer = new byte[data.Length];
                                int len = stream.Read(resultBuffer, 0, resultBuffer.Length);
                                outputStream.Write(resultBuffer, 0, len);
                                outputStream.Flush();
                                return outputStream.ToArray();
                            }
                        }
                    }
                }
                
            }

        }

        /// <summary>
        /// Generates a random key and initialization vector
        /// </summary>
        /// <returns>
        /// The key and initialization vector.
        /// </returns>
        public SymmetricKey GenerateSymmetricKey()
        {
            using (AesCryptoServiceProvider provider = new AesCryptoServiceProvider())
            {
                provider.KeySize = 256;
                provider.GenerateKey();
                SymmetricKey key = new SymmetricKey(provider.Key, provider.IV);
                return key;
            }
        }


        public class SymmetricKey
        {
            /// <summary>
            /// The key.
            /// </summary>
            private byte[] key;

            /// <summary>
            /// The initialization vector.
            /// </summary>
            private byte[] iv;

            /// <summary>
            /// Initializes a new instance of the <see cref="SymmetricKey"/> class.
            /// </summary>
            public SymmetricKey()
            {
            }

            /// <summary>
            /// Initializes a new instance of the <see cref="SymmetricKey"/> class.
            /// </summary>
            /// <param name="key">The key.</param>
            /// <param name="iv">The iv.</param>
            public SymmetricKey(byte[] key, byte[] iv)
            {
                this.Init(key, iv);
            }

            /// <summary>
            /// Gets the key.
            /// </summary>
            [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1819:PropertiesShouldNotReturnArrays", Justification = "Byte[] is what the providers need")]
            public byte[] Key
            {
                get { return this.key; }
            }

            /// <summary>
            /// Gets the iv.
            /// </summary>
            [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1819:PropertiesShouldNotReturnArrays", Justification = "Byte[] is what the providers need")]
            public byte[] IV
            {
                get { return this.iv; }
            }

            /// <summary>
            /// Loads the specified key and iv
            /// </summary>
            /// <param name="newKey">The key.</param>
            /// <param name="newIV">The iv.</param>
            public void Init(byte[] newKey, byte[] newIV)
            {
                this.key = newKey;
                this.iv = newIV;
            }


            public void fromByteArray(byte[] ba)
            {
                byte keyLen = ba[0];
                byte ivLen = ba[1];
                key = new byte[keyLen];
                iv = new byte[ivLen];
                for (int i = 0; i < keyLen; i++)
                {
                    key[i] = ba[2 + i];
                }

                for (int i = 0; i < ivLen; i++)
                {
                    iv[i] = ba[2 + i + keyLen];
                }

            }


            public byte[] toByteArray()
            {
                byte[] res = new byte[key.Length + iv.Length + 2];
                res[0] = (byte)key.Length;
                res[1] = (byte)iv.Length;
                for (int i = 0; i < key.Length; i++)
                {
                    res[2 + i] = key[i];
                }
                for (int i = 0; i < iv.Length; i++)
                {
                    res[2 + i + key.Length] = iv[i];
                }
                return res;
            }
        }

    }
}
