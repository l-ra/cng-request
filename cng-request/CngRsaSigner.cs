using System;
using System.IO;
using System.Collections;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.Utilities;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Digests;



namespace test_key_access
{

    class CngSigCalculator : IStreamCalculator
    {
        private readonly ISigner sig;
        private readonly Stream stream;

        public CngSigCalculator(ISigner sig)
        {
            this.sig = sig;
            this.stream = new CngSignerBucket(sig);
        }

        public Stream Stream
        {
            get { return stream; }
        }

        public object GetResult()
        {
            return new CngSigResult(sig);
        }
    }


    class CngSigResult : IBlockResult
    {
        private readonly ISigner sig;

        internal CngSigResult(ISigner sig)
        {
            this.sig = sig;
        }

        public byte[] Collect()
        {
            return sig.GenerateSignature();
        }

        public int Collect(byte[] destination, int offset)
        {
            byte[] signature = Collect();

            Array.Copy(signature, 0, destination, offset, signature.Length);

            return signature.Length;
        }
    }
    class CngSignerBucket
        : Stream
    {
        protected readonly ISigner signer;

        public CngSignerBucket(
            ISigner signer)
        {
            this.signer = signer;
        }

        public override int Read(
            byte[] buffer,
            int offset,
            int count)
        {
            throw new NotImplementedException();
        }

        public override int ReadByte()
        {
            throw new NotImplementedException();
        }

        public override void Write(
            byte[] buffer,
            int offset,
            int count)
        {
            if (count > 0)
            {
                signer.BlockUpdate(buffer, offset, count);
            }
        }

        public override void WriteByte(
            byte b)
        {
            signer.Update(b);
        }

        public override bool CanRead
        {
            get { return false; }
        }

        public override bool CanWrite
        {
            get { return true; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public override long Length
        {
            get { return 0; }
        }

        public override long Position
        {
            get { throw new NotImplementedException(); }
            set { throw new NotImplementedException(); }
        }

        public override void Flush()
        {
        }

        public override long Seek(
            long offset,
            SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(
            long length)
        {
            throw new NotImplementedException();
        }
    }


    public class CngAsn1SignatureFactory : ISignatureFactory
    {
        Asn1SignatureFactory fact;
        AsymmetricKeyParameter key;

        public CngAsn1SignatureFactory(string algorithm, AsymmetricKeyParameter key)
        {
            fact = new Asn1SignatureFactory(algorithm, key);
            this.key = key;
        }

        public object AlgorithmDetails
        {
            get { return fact.AlgorithmDetails; }
        }


        public IStreamCalculator CreateCalculator()
        {
            ISigner sig = new RSACngDigestSigner();
            ICipherParameters cp = key;
            sig.Init(true, cp);
            return new CngSigCalculator(sig);
        }
    }


    public class RSACngAsymmetricKeyParameter : AsymmetricKeyParameter
    {
        RSACngCipherParameters key;

        public RSACng CngKey { get { return key.Key; } }

        public RSACngAsymmetricKeyParameter(RSACngCipherParameters key):base(true)
        {
            this.key = key;
        }

        public override bool Equals(object obj)
        {

            return base.Equals(obj);
        }
        public override int GetHashCode()
        {
            return base.GetHashCode();
        }

        public override string ToString()
        {
            return base.ToString();
        }
    }


    public class RSACngCipherParameters : ICipherParameters
    {
        public RSACng Key{
            get;
        }

        public RSACngCipherParameters(RSACng key)
        {
            Key = key;
        }
    } 

    public class RSACngAsymmetricBlockCipher : IAsymmetricBlockCipher
    {
        RSACng key;
        bool forEncryption;
        int bitSize;

        public virtual string AlgorithmName
        {
            get { return "RSA"; }
        }

        public virtual int GetInputBlockSize()
        {
            if (forEncryption)
            {
                return (bitSize - 1) / 8;
            }

            return (bitSize + 7) / 8;
        }

        public int GetOutputBlockSize()
        {
            if (forEncryption)
            {
                return (bitSize + 7) / 8;
            }

            return (bitSize - 1) / 8;
        }

        public void Init(bool forEncryption, ICipherParameters parameters)
        {
            if (parameters is ParametersWithRandom)
            {
                parameters = ((ParametersWithRandom)parameters).Parameters;
            }

            switch (parameters) {
                case RSACngAsymmetricKeyParameter rsa:
                    this.key = rsa.CngKey;
                    this.forEncryption = forEncryption;
                    this.bitSize = key.KeySize;
                    break;
                default:
                    throw new InvalidKeyException("Not an RSACng key");
            }
        }

        public byte[] ProcessBlock(byte[] inBuf, int inOff, int inLen)
        {
            byte[] data = Arrays.CopyOfRange(inBuf, inOff, inOff + inLen);

            if (forEncryption)
            {
                var purehash = Arrays.CopyOfRange(data, data.Length - 32, data.Length);
                return key.SignHash(purehash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); 
            }
            else
            {
                return key.EncryptValue(data);
            }
        }
    }


    public class RSACngDigestSigner
       : ISigner
    {
        private readonly IAsymmetricBlockCipher rsaEngine =  new RSACngAsymmetricBlockCipher();
        private readonly AlgorithmIdentifier algId;
        private readonly IDigest digest;
        private bool forSigning;

        private static readonly IDictionary oidMap = new Hashtable();

        /// <summary>
        /// Load oid table.
        /// </summary>
        static RSACngDigestSigner()
        {
            oidMap["RIPEMD128"] = TeleTrusTObjectIdentifiers.RipeMD128;
            oidMap["RIPEMD160"] = TeleTrusTObjectIdentifiers.RipeMD160;
            oidMap["RIPEMD256"] = TeleTrusTObjectIdentifiers.RipeMD256;

            oidMap["SHA-1"] = X509ObjectIdentifiers.IdSha1;
            oidMap["SHA-224"] = NistObjectIdentifiers.IdSha224;
            oidMap["SHA-256"] = NistObjectIdentifiers.IdSha256;
            oidMap["SHA-384"] = NistObjectIdentifiers.IdSha384;
            oidMap["SHA-512"] = NistObjectIdentifiers.IdSha512;

            oidMap["MD2"] = PkcsObjectIdentifiers.MD2;
            oidMap["MD4"] = PkcsObjectIdentifiers.MD4;
            oidMap["MD5"] = PkcsObjectIdentifiers.MD5;
        }

        public RSACngDigestSigner() : this(new Sha256Digest()) { }

        public RSACngDigestSigner(IDigest digest)
            : this(digest, (DerObjectIdentifier)oidMap[digest.AlgorithmName])
        {
        }

        public RSACngDigestSigner(IDigest digest, DerObjectIdentifier digestOid)
            : this(digest, new AlgorithmIdentifier(digestOid, DerNull.Instance))
        {
        }

        public RSACngDigestSigner(IDigest digest, AlgorithmIdentifier algId)
        {
            this.digest = digest;
            this.algId = algId;
        }

        public virtual string AlgorithmName
        {
            get { return digest.AlgorithmName + "withRSA"; }
        }

        /**
         * Initialise the signer for signing or verification.
         *
         * @param forSigning true if for signing, false otherwise
         * @param param necessary parameters.
         */
        public virtual void Init(
            bool forSigning,
            ICipherParameters parameters)
        {
            this.forSigning = forSigning;
            AsymmetricKeyParameter k;

            if (parameters is ParametersWithRandom)
            {
                k = (AsymmetricKeyParameter)((ParametersWithRandom)parameters).Parameters;
            }
            else
            {
                k = (AsymmetricKeyParameter)parameters;
            }

            if (forSigning && !k.IsPrivate)
                throw new InvalidKeyException("Signing requires private key.");

            if (!forSigning && k.IsPrivate)
                throw new InvalidKeyException("Verification requires public key.");

            Reset();

            rsaEngine.Init(forSigning, parameters);
        }

        /**
         * update the internal digest with the byte b
         */
        public virtual void Update(
            byte input)
        {
            digest.Update(input);
        }

        /**
         * update the internal digest with the byte array in
         */
        public virtual void BlockUpdate(
            byte[] input,
            int inOff,
            int length)
        {
            digest.BlockUpdate(input, inOff, length);
        }

        /**
         * Generate a signature for the message we've been loaded with using
         * the key we were initialised with.
         */
        public virtual byte[] GenerateSignature()
        {
            if (!forSigning)
                throw new InvalidOperationException("RsaDigestSigner not initialised for signature generation.");

            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            byte[] data = DerEncode(hash);
            return rsaEngine.ProcessBlock(data, 0, data.Length);
        }

        /**
         * return true if the internal state represents the signature described
         * in the passed in array.
         */
        public virtual bool VerifySignature(
            byte[] signature)
        {
            if (forSigning)
                throw new InvalidOperationException("RsaDigestSigner not initialised for verification");

            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            byte[] sig;
            byte[] expected;

            try
            {
                sig = rsaEngine.ProcessBlock(signature, 0, signature.Length);
                expected = DerEncode(hash);
            }
            catch (Exception)
            {
                return false;
            }

            if (sig.Length == expected.Length)
            {
                return Arrays.ConstantTimeAreEqual(sig, expected);
            }
            else if (sig.Length == expected.Length - 2)  // NULL left out
            {
                int sigOffset = sig.Length - hash.Length - 2;
                int expectedOffset = expected.Length - hash.Length - 2;

                expected[1] -= 2;      // adjust lengths
                expected[3] -= 2;

                int nonEqual = 0;

                for (int i = 0; i < hash.Length; i++)
                {
                    nonEqual |= (sig[sigOffset + i] ^ expected[expectedOffset + i]);
                }

                for (int i = 0; i < sigOffset; i++)
                {
                    nonEqual |= (sig[i] ^ expected[i]);  // check header less NULL
                }

                return nonEqual == 0;
            }
            else
            {
                return false;
            }
        }

        public virtual void Reset()
        {
            digest.Reset();
        }

        private byte[] DerEncode(byte[] hash)
        {
            if (algId == null)
            {
                // For raw RSA, the DigestInfo must be prepared externally
                return hash;
            }

            DigestInfo dInfo = new DigestInfo(algId, hash);

            return dInfo.GetDerEncoded();
        }
    }



}
