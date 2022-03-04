using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace CryptoLib
{
    public class X
    {

        public static string RsaGetPubParsXml(RSACryptoServiceProvider rsa)
        {
            bool isPriv = false;
            RSAParameters pars = new RSAParameters();
            pars.Exponent = rsa.ExportParameters(isPriv).Exponent;
            pars.Modulus = rsa.ExportParameters(isPriv).Modulus;
            return RsaParsToXml(pars);
        }
        private static string RsaParsToXml(RSAParameters pars)
        {
            var serializer = new XmlSerializer(typeof(RSAParameters));
            var settings = new XmlWriterSettings
            {
                Encoding = new UTF8Encoding(true),
                Indent = false,
                NewLineHandling = NewLineHandling.None
            };
            using (var sw = new Utf8StringWriter())
            {
                using (var xmlw = XmlWriter.Create(sw, settings))
                {
                    serializer.Serialize(xmlw, pars);
                }
                return sw.ToString();
            }
        }
        private static RSAParameters RsaParsFromXml(string data)
        {
            XmlSerializer xml = new XmlSerializer(typeof(RSAParameters));
            object res;
            using (TextReader reader = new StringReader(data))
            {
                res = xml.Deserialize(reader);
            }
            return (RSAParameters)res;
        }

        public static string RsaEncrypt(string text, string pubParsXml)
        {
            var pubPars = RsaParsFromXml(pubParsXml);
            byte[] data = Encoding.Default.GetBytes(text);
            using (RSACryptoServiceProvider cservprov = new RSACryptoServiceProvider())
            {
                cservprov.ImportParameters(pubPars);
                byte[] enc = cservprov.Encrypt(data, false);
                return Convert.ToBase64String(enc, 0, enc.Length);
            }
        }

        public static string RsaDecrypt(string code, RSACryptoServiceProvider rsa)
        {
            byte[] enc = Convert.FromBase64String(code);
            byte[] dec = rsa.Decrypt(enc, false);
            return Encoding.UTF8.GetString(dec);
        }
        public static string SignedData(string text, RSACryptoServiceProvider rsa)
        {
            byte[] data = Encoding.Default.GetBytes(text);
            byte[] xdata = rsa.SignData(data, new SHA1CryptoServiceProvider());
            return Convert.ToBase64String(xdata, 0, xdata.Length);
        }
        public static bool VerifyData(string text, string signedText, string pubParsXml)
        {
            byte[] signed = Convert.FromBase64String(signedText);
            byte[] data = Encoding.Default.GetBytes(text);
            RSACryptoServiceProvider cservprov = new RSACryptoServiceProvider();
            var pubParams = RsaParsFromXml(pubParsXml);
            cservprov.ImportParameters(pubParams);
            return cservprov.VerifyData(data, new SHA1CryptoServiceProvider(), signed);
        }


        public static string AesEncrypt(string msg, string pwd, out string iv)
        {
            byte[] res = null;
            iv = "";
            using (Aes aes = Aes.Create())
            {
                byte[] key = Encoding.UTF8.GetBytes(pwd);
                Array.Resize(ref key, 32);
                iv = Convert.ToBase64String(aes.IV);
                aes.Key = key;
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                        {
                            sw.Write(msg);
                        }
                        res = ms.ToArray();
                    }
                }
            }
            return Convert.ToBase64String(res);    
        }
        public static string AesDecrypt(string enc, string pwd, string sal)
        {
            var texto = String.Empty;
            using (Aes aes = Aes.Create())
            {
                byte[] key = Encoding.UTF8.GetBytes(pwd);
                Array.Resize(ref key, 32);
                aes.Key = key;
                aes.IV = Convert.FromBase64String(sal);
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(enc)))
                {
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader sr = new StreamReader(cs))
                        {
                            texto = sr.ReadToEnd();
                        }
                    }
                }
            }
            return texto;
        }

        public static string ShaHash(Object input)
        {
            var res = new StringBuilder();
            using (var sha = SHA256.Create())
            {
                
                var hash = sha.ComputeHash(Encoding.UTF8.GetBytes((String)input));
                for (int i = 0; i < hash.Length; i++)
                {
                    res.Append(hash[i].ToString("x2"));
                }
            }
            return res.ToString();
        }

        public static string RandomString(int length)
        {
            const string valid = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            StringBuilder res = new StringBuilder();
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] uintBuffer = new byte[sizeof(uint)];

                while (length-- > 0)
                {
                    rng.GetBytes(uintBuffer);
                    uint num = BitConverter.ToUInt32(uintBuffer, 0);
                    res.Append(valid[(int)(num % (uint)valid.Length)]);
                }
            }
            return res.ToString();
        }

    }

    public class Utf8StringWriter : StringWriter
    {
        public override Encoding Encoding => Encoding.UTF8;

    }
}
