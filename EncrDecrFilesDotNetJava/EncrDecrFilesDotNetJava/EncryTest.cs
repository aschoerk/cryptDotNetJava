using System;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EncrDecrDotNetJava
{
    [TestClass]
    public class EncryTest
    {
        [TestMethod]
        public void TestMethod1()
        {
            string xmlPublic = System.IO.File.ReadAllText(@"../../publicKey.xml");

            byte[] toEncrypt = System.IO.File.ReadAllBytes(@"../../example.jpg");

            AsymmetricEncryptor encryptor = new AsymmetricEncryptor();

            byte[] combined = encryptor.EncryptAssymetricByPublic(toEncrypt, xmlPublic);

            System.IO.File.WriteAllBytes(@"../../example.encrypted", combined);


            string xmlPrivate = System.IO.File.ReadAllText(@"../../privateKey.xml");
            byte[] toDecrypt = System.IO.File.ReadAllBytes(@"../../example.encrypted");
            byte[] decrypted = encryptor.DecryptTestWise(toDecrypt, xmlPrivate);

            Assert.AreEqual(toEncrypt.Length, decrypted.Length);
            for (int i = 0; i < toEncrypt.Length; i++)
            {
                Assert.AreEqual(toEncrypt[i], decrypted[i]);
            }
        }
    }
}
