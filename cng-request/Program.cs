using System;
using System.Collections;
using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;


namespace test_key_access
{

    class Program
    {
        static void Main(string[] args)
        {

            try
            {
                var keyName = args[0];
                var providerName = args[1];
                var subject = args[2];

                /*
                // generate
                var parms = new CngKeyCreationParameters();
                parms.Provider = new CngProvider(providerName);
                parms.KeyCreationOptions = CngKeyCreationOptions.None;
                parms.ExportPolicy = CngExportPolicies.None;
                parms.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(4096), CngPropertyOptions.None));
                CngKey.Create(CngAlgorithm.Rsa, keyName, parms);

                return;
                
                 */


                var key = CngKey.Open(keyName, new CngProvider(providerName));
                var rsa = new RSACng(key);
                Console.WriteLine($"key loades {key.Algorithm}, {key.Provider}, {rsa.KeySize} ");
                var data = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
                var encrypted = rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
                Console.WriteLine("encrypt OK");
                var decrypted = rsa.Decrypt(encrypted, RSAEncryptionPadding.Pkcs1);
                Console.WriteLine("decrypt OK");

                var signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                Console.WriteLine("sign OK");
                var verifyResult = rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                Console.WriteLine($"verify {verifyResult}");

                var publc = rsa.ExportParameters(false);
                var modulusBytes = new byte[publc.Modulus.Length + 1];
                publc.Modulus.CopyTo(modulusBytes, 1);
                var modulus = new BigInteger(modulusBytes);
                var exponent = new BigInteger(publc.Exponent);
                var rsaPub = new RsaKeyParameters(false, modulus, exponent);

                var rsaPrivParams = new RSACngAsymmetricKeyParameter(new RSACngCipherParameters(rsa));

                var sigFact = new CngAsn1SignatureFactory("SHA256WITHRSA", rsaPrivParams);
                var name = new X509Name(subject);

                var extOids = new ArrayList();
                var extValues = new ArrayList();

                extOids.Add(X509Extensions.KeyUsage);
                var keyUsage = new KeyUsage(KeyUsage.NonRepudiation);
                var keyUsageBytes = keyUsage.GetDerEncoded();

                extValues.Add(new X509Extension(true, new DerOctetString(keyUsageBytes)));

                var extensions = new X509Extensions(extOids, extValues);

                var extensionRequestAttribute = new AttributeX509(new DerObjectIdentifier("1.2.840.113549.1.9.14"), new DerSet(extensions));

                var attrsSet = new DerSet(extensionRequestAttribute);

                var pkcs10 = new Pkcs10CertificationRequest(sigFact, name, rsaPub, attrsSet);
            
                var request = pkcs10.GetDerEncoded();
                File.WriteAllText("req.b64",Convert.ToBase64String(request));

            }
            catch (Exception e)
            {
                Console.WriteLine($"Exception {e.Message}: {e.StackTrace}");
            }
        }
    }
}
