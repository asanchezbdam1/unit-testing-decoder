using System.Security.Cryptography;
using NUnit.Framework;

namespace CryptoLib.Tests
{
    [TestFixture]
    public class Tests
    {
        public RSACryptoServiceProvider rsa1;
        public RSACryptoServiceProvider rsa2;
        public string pub1;
        public string pub2;

        public string txt = @"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec vitae velit dictum, lacinia neque at, rhoncus ipsum. Nullam tellus urna, 
dictum ut elit eget, dapibus cursus lectus. Nullam pellentesque, purus non venenatis rhoncus, sapien lectus semper orci, et fringilla enim 
elit ac ipsum. Duis scelerisque congue odio, eget tincidunt tortor pellentesque varius. Maecenas commodo arcu ligula, in pretium ligula 
hendrerit et. Maecenas gravida ligula tortor, in bibendum felis auctor venenatis. Maecenas luctus, velit at semper accumsan, diam sapien 
rutrum est, commodo imperdiet tortor nulla eget ante.

Aliquam laoreet massa urna, ac aliquet justo convallis a. In placerat magna lorem, eu interdum purus feugiat non. Integer tincidunt nulla id 
volutpat vulputate. Vestibulum non vulputate dolor. Duis eu est nibh. Suspendisse vel luctus felis. Proin consequat commodo libero a blandit. 
Aenean vel lacus tellus. Duis scelerisque rhoncus dictum.

Nam in faucibus felis. Nam volutpat risus dolor, tempus sodales justo luctus eu. Fusce feugiat est sit amet eleifend faucibus. Orci varius 
natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Phasellus feugiat malesuada est ut dapibus. Pellentesque elementum 
nisl nibh, at tempor enim imperdiet vitae. In tristique ante nisl, in faucibus mauris sodales ut. Proin mauris justo, finibus at mattis nec, 
condimentum quis ex. Sed ac luctus purus, quis iaculis mi. Sed sollicitudin semper dui vel tristique.

Maecenas ut libero ut turpis euismod tincidunt eu sed ex. Sed vehicula ligula eget euismod pretium. Integer neque ante, dignissim at odio eget, 
mollis convallis sapien. Aenean quis dolor at est hendrerit commodo. Phasellus finibus rhoncus sem, quis pharetra felis mollis eget. Cras ex 
dolor, tempus at facilisis at, iaculis nec est. Vestibulum vitae enim at lorem maximus fringilla non a nulla. Aenean eget massa pharetra, 
vulputate lorem in, congue mi. Pellentesque feugiat ut nisi nec venenatis. Nunc aliquam ornare metus, eget commodo leo interdum eget. Duis 
aliquam, mi eu volutpat dictum, libero lacus aliquam lacus, quis elementum magna magna id lorem. Sed posuere odio a enim elementum, nec 
convallis diam blandit. Quisque porttitor elit vel est tincidunt egestas.

Phasellus eget nunc magna. In tincidunt vestibulum lectus, non aliquam quam volutpat vel. Sed diam lectus, consequat sed pulvinar id, cursus 
faucibus tellus. Suspendisse volutpat accumsan ante. Integer cursus diam ut sollicitudin placerat. Praesent id orci et diam finibus auctor. 
Phasellus molestie faucibus cursus.";

        [SetUp]
        public void Setup()
        {
            rsa1 = new RSACryptoServiceProvider(3072);
            rsa2 = new RSACryptoServiceProvider(3072);
            pub1 = X.RsaGetPubParsXml(rsa1);
            pub2 = X.RsaGetPubParsXml(rsa2);
        }

        [TestCase("Hola mundo!")]
        [TestCase("Hello world!")]
        public void Test_Aes(string msg)
        {
            string pwd = "P4t4t4s!P4t4t4s!";
            string iv = "";
            string encripted = X.AesEncrypt(msg, pwd, out iv);
            string decripted = X.AesDecrypt(encripted, pwd, iv);
            Assert.IsTrue(decripted.Equals(msg), "Encriptación y desencriptación con AES.");
        }

        [TestCase("Hola mundo!")]
        [TestCase("Hello world!")]
        public void Test_Rsa(string msg)
        {
            string encripted = X.RsaEncrypt(msg, pub2);
            string decripted = X.RsaDecrypt(encripted, rsa2);
            Assert.IsTrue(decripted.Equals(msg), "Encriptación y desencriptación con RSA.");
        }

        [TestCase("Hola mundo!")]
        [TestCase("Hello world!")]
        public void Test_Sign(string msg)
        {
            string signed = X.SignedData(msg, rsa1);
            bool b = X.VerifyData(msg, signed, pub1);
            Assert.IsTrue(b, "Firma y verificación con RSA.");
        }

        [TestCase("Hola mundo!", ExpectedResult = "1e479f4d871e59e9054aad62105a259726801d5f494acbfcd40591c82f9b3136")]
        [TestCase("Hola Mundo!", ExpectedResult = "d4962daf2b2f39666bcd8d35df1357c5608b7019791c20812cd9108b830388bc")]
        public string Test_Sha256(string msg)
        {
            return X.ShaHash(msg);
        }

        [Test]
        public void Test_Hybrid()
        {
            // Acciones realizadas en el extremo 1
            string pwd = X.RandomString(140);
            string sha = X.ShaHash(pwd);
            string enc = X.RsaEncrypt(pwd, pub2);
            string sgn = X.SignedData(sha, rsa1);
            string iv;
            string msg = X.AesEncrypt(txt, pwd, out iv);
            string sgm = X.SignedData(txt, rsa1);
            // Acciones realizadas en el extremo 2
            string pw = X.RsaDecrypt(enc, rsa2);
            string hash = X.ShaHash(pw);
            bool b1 = X.VerifyData(hash, sgn, pub1);
            Assert.IsTrue(b1, "El hash firmado por 1 es correcto");
            string dec = X.AesDecrypt(msg, pw, iv);
            bool b2 = X.VerifyData(dec, sgm, pub1);
            Assert.IsTrue(b2, "El mensaje firmado por 1 es correcto");
            // Verificación final
            bool b = dec.Equals(txt);
            Assert.IsTrue(b, "El mensaje desencriptado por 2 es el encriptado por 1.");
        }
    }
}