using System.Text;
using System.Security.Cryptography;

namespace EncryptionLibrary
{
    public class EncryptionLibrary
    {
        #region AES Encryption Class
        //*********  AES Encryption Class  ****************** //Working - Refined - Finished

        public class AESEncryption
        {
            private byte[] SALT { get; set; }
            private byte[] KEY { get; set; }
            private byte[] IV { get; set; }
            private byte[]? CLEARBYTES { get; set; }  //? is nullable
            private byte[]? CIPHERBYTES { get; set; } //? is nullable

            public AESEncryption()
            {
                string password_passphrase = "Sample Passphrase";
                SALT = new byte[] { 0x43, 0x61, 0x70, 0x74, 0x52, 0x65, 0x6E, 0x65, 0x67, 0x61, 0x64, 0x65, 0x20, 0x46, 0x6F, 0x72, 0x65, 0x76, 0x65, 0x72, 0x21 };

                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password_passphrase, SALT, 10000, HashAlgorithmName.SHA512);

                KEY = pdb.GetBytes(32);
                IV = pdb.GetBytes(16);

            }
            public AESEncryption(string password_passphrase)
            {
                SALT = new byte[] { 0x43, 0x61, 0x70, 0x74, 0x52, 0x65, 0x6E, 0x65, 0x67, 0x61, 0x64, 0x65, 0x20, 0x46, 0x6F, 0x72, 0x65, 0x76, 0x65, 0x72, 0x21 };

                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password_passphrase, SALT, 10000, HashAlgorithmName.SHA512);

                KEY = pdb.GetBytes(32);
                IV = pdb.GetBytes(16);

            }
            public AESEncryption(string password_passphrase, string _salt)
            {
                SALT = Encoding.UTF8.GetBytes(_salt);

                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password_passphrase, SALT, 10000, HashAlgorithmName.SHA512);

                KEY = pdb.GetBytes(32);
                IV = pdb.GetBytes(16);

            }
            public string Encrypt(string clearText)
            {
                string encryptedText;
                CLEARBYTES = Encoding.Unicode.GetBytes(clearText);
                using (Aes encryptor = Aes.Create())
                {
                    encryptor.Key = KEY;
                    encryptor.IV = IV;

                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(CLEARBYTES, 0, CLEARBYTES.Length);
                            cs.Close();
                        }
                        encryptedText = Convert.ToBase64String(ms.ToArray());
                    }
                }
                return encryptedText;
            }

            public string Decrypt(string encryptedText)
            {
                string clearText;
                CIPHERBYTES = Convert.FromBase64String(encryptedText);
                using (Aes encryptor = Aes.Create())
                {
                    encryptor.Key = KEY;
                    encryptor.IV = IV;

                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(CIPHERBYTES, 0, CIPHERBYTES.Length);
                            cs.Close();
                        }
                        clearText = Encoding.Unicode.GetString(ms.ToArray());
                    }
                }
                return clearText;
            }

        }
        #endregion

        #region AES-GCM Encryption Class
        //*********  AES-GCM Encryption Class  ****************** //Working - Refined - Finished

        public class AES_GCM
        {
            private byte[] SALT { get; set; }
            private byte[] KEY { get; set; }
            private byte[] TAG { get; set; }
            private byte[] NONCE { get; set; }
            private byte[]? CLEARBYTES { get; set; }  //? is nullable
            private byte[]? CIPHERBYTES { get; set; } //? is nullable


            public AES_GCM()
            {
                string password_passphrase = "Sample Passphrase";
                SALT = new byte[] { 0x43, 0x61, 0x70, 0x74, 0x52, 0x65, 0x6E, 0x65, 0x67, 0x61, 0x64, 0x65, 0x20, 0x46, 0x6F, 0x72, 0x65, 0x76, 0x65, 0x72, 0x21 };

                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password_passphrase, SALT, 10000, HashAlgorithmName.SHA512);

                KEY = pdb.GetBytes(32);
                TAG = new byte[16];
                NONCE = pdb.GetBytes(12);

            }
            public AES_GCM(string password_passphrase)
            {

                SALT = new byte[] { 0x43, 0x61, 0x70, 0x74, 0x52, 0x65, 0x6E, 0x65, 0x67, 0x61, 0x64, 0x65, 0x20, 0x46, 0x6F, 0x72, 0x65, 0x76, 0x65, 0x72, 0x21 };

                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password_passphrase, SALT, 10000, HashAlgorithmName.SHA512);

                KEY = pdb.GetBytes(32);
                TAG = new byte[16];
                NONCE = pdb.GetBytes(12);

            }
            public AES_GCM(string password_passphrase, string _salt)
            {

                SALT = Encoding.UTF8.GetBytes(_salt);

                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password_passphrase, SALT, 10000, HashAlgorithmName.SHA512);

                KEY = pdb.GetBytes(32);
                TAG = new byte[16];
                NONCE = pdb.GetBytes(12);

            }
            public string Encrypt(string clearText)
            {
                string encryptedText = "";

                CLEARBYTES = Encoding.UTF8.GetBytes(clearText);

                CIPHERBYTES = new byte[CLEARBYTES.Length];


                using (AesGcm aesgcm = new AesGcm(KEY))
                {
                    aesgcm.Encrypt(NONCE, CLEARBYTES, CIPHERBYTES, TAG);

                    encryptedText = Convert.ToBase64String(CIPHERBYTES);

                }

                return encryptedText;
            }

            public string Decrypt(string encryptedText)
            {

                string clearText = "";

                CIPHERBYTES = Convert.FromBase64String(encryptedText);
                CLEARBYTES = new byte[CIPHERBYTES.Length];

                using (AesGcm aesgcm = new AesGcm(KEY))
                {
                    aesgcm.Decrypt(NONCE, CIPHERBYTES, TAG, CLEARBYTES);

                    clearText = Encoding.UTF8.GetString(CLEARBYTES);

                }

                return clearText;

            }
        }
        #endregion

        #region TripleDES Encryption Class
        //*********  TripleDES Encryption Class  ****************** //Working!
        public sealed class tripleDES
        {
            private TripleDES TripleDes = TripleDES.Create();

            private byte[] TruncateHash(string key, int length)
            {
                //Originally SHA1
                using (SHA512 sha512 = SHA512.Create())
                {
                    // Hash the key.
                    byte[] keyBytes = Encoding.Unicode.GetBytes(key);
                    byte[] hash = sha512.ComputeHash(keyBytes);
                    var oldHash = hash;
                    hash = new byte[length - 1 + 1];

                    // Truncate or pad the hash.
                    if (oldHash != null)
                        Array.Copy(oldHash, hash, Math.Min(length - 1 + 1, oldHash.Length));
                    return hash;
                }

            }

            public tripleDES(string key)
            {
                // Initialize the crypto provider.
                    TripleDes.Key = TruncateHash(key, TripleDes.KeySize / 8);
                    TripleDes.IV = TruncateHash("", TripleDes.BlockSize / 8);
            }


            public string TripleDESEncrypt(string plaintext)
            {

                // Convert the plaintext string to a byte array.
                byte[] plaintextBytes = Encoding.Unicode.GetBytes(plaintext);

                // Create the stream.
                using MemoryStream ms = new MemoryStream();
                {
                    // Create the encoder to write to the stream.
                   using CryptoStream encStream = new CryptoStream(ms, TripleDes.CreateEncryptor(), CryptoStreamMode.Write);
                    {
                        // Use the crypto stream to write the byte array to the stream.
                        encStream.Write(plaintextBytes, 0, plaintextBytes.Length);
                        encStream.FlushFinalBlock();
                    }
                }

                // Convert the encrypted stream to a printable string.
                return Convert.ToBase64String(ms.ToArray());
            }

            public string TripleDESDecrypt(string encryptedtext)
            {

                // Convert the encrypted text string to a byte array.
                byte[] encryptedBytes = Convert.FromBase64String(encryptedtext);

                // Create the stream.
                using MemoryStream ms = new MemoryStream();
                {
                    // Create the decoder to write to the stream.
                    using CryptoStream decStream = new CryptoStream(ms, TripleDes.CreateDecryptor(), CryptoStreamMode.Write);
                    {
                        // Use the crypto stream to write the byte array to the stream.
                        decStream.Write(encryptedBytes, 0, encryptedBytes.Length);
                        decStream.FlushFinalBlock();
                    }
                }
                // Convert the plaintext stream to a string.
                return Encoding.Unicode.GetString(ms.ToArray());
            }
        }
        #endregion

        #region CHACHA20POLY1305 Encryption Class
        //*********  CHACHA20POLY1305 Encryption Class  ****************** //Not Supported Platform Error - Refined - Finished

        public class CHACHA20POLY1305
        {

            private byte[] SALT { get; set; }
            private byte[] KEY { get; set; }
            private byte[] TAG { get; set; }
            private byte[] NONCE { get; set; }
            private byte[]? CLEARBYTES { get; set; }  //? is nullable
            private byte[]? CIPHERBYTES { get; set; } //? is nullable


            public CHACHA20POLY1305()
            {
                string password_passphrase = "Sample Passphrase";
                SALT = new byte[] { 0x43, 0x61, 0x70, 0x74, 0x52, 0x65, 0x6E, 0x65, 0x67, 0x61, 0x64, 0x65, 0x20, 0x46, 0x6F, 0x72, 0x65, 0x76, 0x65, 0x72, 0x21 };

                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password_passphrase, SALT, 10000, HashAlgorithmName.SHA512);

                KEY = pdb.GetBytes(32);
                TAG = new byte[16];
                NONCE = pdb.GetBytes(12);

            }
            public CHACHA20POLY1305(string password_passphrase)
            {

                SALT = new byte[] { 0x43, 0x61, 0x70, 0x74, 0x52, 0x65, 0x6E, 0x65, 0x67, 0x61, 0x64, 0x65, 0x20, 0x46, 0x6F, 0x72, 0x65, 0x76, 0x65, 0x72, 0x21 };

                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password_passphrase, SALT, 10000, HashAlgorithmName.SHA512);

                KEY = pdb.GetBytes(32);
                TAG = new byte[16];
                NONCE = pdb.GetBytes(12);

            }
            public CHACHA20POLY1305(string password_passphrase, string _salt)
            {

                SALT = Encoding.UTF8.GetBytes(_salt);

                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password_passphrase, SALT, 10000, HashAlgorithmName.SHA512);

                KEY = pdb.GetBytes(32);
                TAG = new byte[16];
                NONCE = pdb.GetBytes(12);

            }
            public string Encrypt(string clearText)
            {
                string encryptedText = "";

                CLEARBYTES = Encoding.UTF8.GetBytes(clearText);
                CIPHERBYTES = new byte[CLEARBYTES.Length];


                using (ChaCha20Poly1305 CHACHA20_POLY1305 = new ChaCha20Poly1305(KEY))
                {
                    CHACHA20_POLY1305.Encrypt(NONCE, CLEARBYTES, CIPHERBYTES, TAG);

                    encryptedText = Convert.ToBase64String(CIPHERBYTES);

                }

                return encryptedText;
            }

            public string Decrypt(string encryptedText)
            {

                string clearText = "";

                CIPHERBYTES = Convert.FromBase64String(encryptedText);
                CLEARBYTES = new byte[CIPHERBYTES.Length];

                using (ChaCha20Poly1305 CHACHA20_POLY1305 = new ChaCha20Poly1305(KEY))
                {
                    CHACHA20_POLY1305.Decrypt(NONCE, CIPHERBYTES, TAG, CLEARBYTES);

                    clearText = Encoding.UTF8.GetString(CLEARBYTES);

                }

                return clearText;

            }
        }
        #endregion

        #region RSA Encryption Class
        //*********  RSA Encryption Class  ****************** //Working!

        //RSA_CSP RSA = new RSA_CSP();

        public class RSA_CSP
        {
            public object PUBKEY { get; set; }
            public object PRIVKEY { get; set; }

            public RSA_CSP()
            {
                //new CSP with a new 2048 bit rsa key pair - example
                var csp = new RSACryptoServiceProvider(2048);
                PRIVKEY = csp.ExportParameters(true);
                PUBKEY = csp.ExportParameters(false);
            }

            public string Encrypt(string clearText, RSAParameters key) //Call as: encryptedString = RSA.Encrypt(clearTextString, (RSAParameters)RSA.PUBKEY);
            {
                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(key);
                    byte[] clearBytes = Encoding.UTF8.GetBytes(clearText);
                    byte[] encryptedText = rsa.Encrypt(clearBytes, false);
                    return Convert.ToBase64String(encryptedText);
                }
            }

            public string Decrypt(string cipherText, RSAParameters key) //Call as: decryptedString = RSA.Decrypt(encryptedString, (RSAParameters)RSA.PRIVKEY);
            {

                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(key);
                    byte[] cipherBytes = Convert.FromBase64String(cipherText);
                    byte[] clearText = rsa.Decrypt(cipherBytes, false);
                    return Encoding.UTF8.GetString(clearText);
                }
            }

        }

        #endregion
    }
}