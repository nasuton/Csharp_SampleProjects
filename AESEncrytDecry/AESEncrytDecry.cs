using System.Security.Cryptography;
using System.Text;

namespace Csharp_SampleProjects.AESEncrytDecry
{
    enum AESType
    {
        AES_128 = 0,
        AES_192 = 1,
        AES_256 = 2,
    }

    internal class AESEncrytDecry
    {
        private string keyValue = string.Empty;

        private string ivValue = string.Empty;

        private int keySize = 0;

        private int ivSize = 0;

        public AESEncrytDecry(string key, string iv, AESType aesType)
        {
            if (key == null || key.Length <= 0 ||  iv == null || iv.Length <= 0) throw new ArgumentException("key or iv is not set");

            switch (aesType)
            {
                // AES-128:Keyの長さは16バイト(半角文字16文字)とIvの長さは16バイト(半角文字16文字)
                case AESType.AES_128:
                    keySize = 16;
                    ivSize = 16;
                    break;

                // AES-192:Keyの長さは24バイト(半角文字24文字)とIvの長さは16バイト(半角文字16文字)
                case AESType.AES_192:
                    keySize = 24;
                    ivSize = 16;
                    break;

                // AES-256:Keyの長さは32バイト(半角文字32文字)とIvの長さは16バイト(半角文字16文字)
                case AESType.AES_256:
                    keySize = 32;
                    ivSize = 16;
                    break;
                // どれにも当てはまらない場合はエラーとする
                default:
                    throw new ArgumentException("aesType is set to an unsupported value");
            }

            if (key.Length != keySize || iv.Length != ivSize) throw new ArgumentException($"The length of the key does not match {keySize}, or the length of the IV does not match {ivSize}. \nThe length of argument 'key' is {key.Length}, and the length of argument 'iv' is {iv.Length}.");

            keyValue = key;
            ivValue = iv;
        }

        /// <summary>
        /// AESで暗号化されたものを復号化
        /// </summary>
        /// <param name="cipherText">AESで暗号化された文字列</param>
        /// <returns>復号化された文字列</returns>
        public string DecryptStringAES(string cipherText)
        {
            if (cipherText == null || cipherText.Length <= 0) throw new ArgumentNullException("No characters are set in cipherText");

            var keyBytes = Encoding.UTF8.GetBytes(keyValue);
            var ivBytes = Encoding.UTF8.GetBytes(ivValue);

            var encrypted = Convert.FromBase64String(cipherText);
            var decriptedFromJavascript = DecryptStringFromBytes(encrypted, keyBytes, ivBytes);
            return decriptedFromJavascript;
        }

        /// <summary>
        /// テキストをAESで暗号化
        /// </summary>
        /// <param name="plainText">平文(暗号化したい文字列)</param>
        /// <returns>暗号化された文字列</returns>
        public string EncryptStringAES(string plainText)
        {
            if (plainText == null || plainText.Length <= 0) throw new ArgumentNullException("No characters are set in plainText");

            var keyBytes = Encoding.UTF8.GetBytes(keyValue);
            var ivBytes = Encoding.UTF8.GetBytes(ivValue);

            var encryptedFromJavascript = EncryptStringToBytes(plainText, keyBytes, ivBytes);
            var decrypted = Convert.ToBase64String(encryptedFromJavascript);
            return decrypted;
        }

        /// <summary>
        /// 引数で受け取ったkeyとivを使用して復号化する
        /// </summary>
        /// <param name="cipherText">AESで暗号化された文字列</param>
        /// <param name="key">byte化されたkey</param>
        /// <param name="iv">byte化されたiv</param>
        /// <returns>復号化された文字列</returns>
        private string DecryptStringFromBytes(byte[] cipherText, byte[] key, byte[] iv)
        {
            string plaintext = string.Empty;

            // 指定されたキーとIVを使用してRijndaelManagedオブジェクトを作成
            using (var rijAlg = new RijndaelManaged())
            {
                // RijndaelManagedの設定
                rijAlg.Mode = CipherMode.CBC;
                rijAlg.Padding = PaddingMode.PKCS7;
                rijAlg.BlockSize = 128;
                // 暗号化方式の文字列の長さを8倍する
                rijAlg.KeySize = keySize * 8;
                rijAlg.Key = key;
                rijAlg.IV = iv;

                var decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            // 復号化されたバイトを復号化ストリームから読み取り、文字列に設定
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }
            return plaintext;
        }

        /// <summary>
        /// 引数で受け取ったkeyとivを使用して暗号化する
        /// </summary>
        /// <param name="plainText">暗号化したり平文</param>
        /// <param name="key">byte化されたkey</param>
        /// <param name="iv">byte化されたiv</param>
        /// <returns>暗号化された文字列</returns>
        private byte[] EncryptStringToBytes(string plainText, byte[] key, byte[] iv)
        {
            byte[] encrypted;

            // 指定されたキーとIVを使用してRijndaelManagedオブジェクトを作成
            using (var rijAlg = new RijndaelManaged())
            {
                rijAlg.Mode = CipherMode.CBC;
                rijAlg.Padding = PaddingMode.PKCS7;
                rijAlg.BlockSize = 128;
                // 暗号化方式の文字列の長さを8倍する
                rijAlg.KeySize = keySize * 8;
                rijAlg.Key = key;
                rijAlg.IV = iv;

                var encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return encrypted;
        }
    }
}
