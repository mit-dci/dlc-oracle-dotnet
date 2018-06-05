    using System;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Custom.Sec;
using Org.BouncyCastle.Crypto.Digests;
using System.Linq;

namespace Mit.Dci.DlcOracle
{
    /// <summary>
    /// This is a static class containing various methods used when creating an Oracle
    /// </summary>
    public static class Oracle
    {
        private static SecureRandom secureRandom = new SecureRandom ();
        private static X9ECParameters curve = SecNamedCurves.GetByName ("secp256k1");
        private static ECDomainParameters domain = new ECDomainParameters (curve.Curve, curve.G, curve.N, curve.H);

        private static BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);

        /// <summary>
        /// Generates a proper byte array for a given numeric value
        /// This because numeric values are expected to be wrapped in a 32 byte
        /// message by LIT
        /// </summary>       
        /// <param name="value">Number to encode</param>
        public static byte[] GenerateNumericMessage(long value) {
            return StringToByteArray(value.ToString("x64"));
        }

        /// <summary>
        /// Derives the public key to a private key
        /// </summary>       
        /// <param name="privateKey">The private key to derive the public key for</param>
        public static byte[] PublicKeyFromPrivateKey(byte[] privateKey) {
            BigInteger d = BigIntegerFromBytes(privateKey);

            ECPoint q = domain.G.Multiply(d).Normalize();
            return q.GetEncoded(true);
        }

        /// <summary>
        /// Will return a new random private scalar to be used when signing a new message
        /// </summary>       
        public static byte[] GenerateOneTimeSigningKey() {
            return secureRandom.GenerateSeed(32);
        }


        /// <summary>
        /// calculates the signature multipled by the generator
        /// point, for an arbitrary message based on pubkey R and pubkey A.
        /// Calculates P = pubR - h(msg, pubR)pubA.
        /// This is used when building settlement transactions and determining the pubkey
        /// to the oracle's possible signatures beforehand. Can be calculated with just
        /// public keys, so by anyone.
        /// </summary>       
        /// <param name="oraclePubA">The oracle's public key</param>
        /// <param name="oraclePubR">The oracle's R-point (public key to the one-time signing key)</param>
        /// <param name="message">The message to compute the signature pubkey for</param>
        public static byte[] ComputeSignaturePubKey(byte[] oraclePubA, byte[] oraclePubR, byte[] message)
        {
            ECPoint A = curve.Curve.DecodePoint(oraclePubA).Normalize();
            ECPoint R = curve.Curve.DecodePoint(oraclePubR).Normalize();
            
            byte[] rX = R.XCoord.ToBigInteger().ToByteArray();
            while(rX[0] == (byte)0) {
                rX = rX.Skip(1).ToArray();
            }
            Sha256Digest myHash = new Sha256Digest();
            myHash.BlockUpdate (message, 0, message.Length);
            myHash.BlockUpdate (rX, 0, rX.Length);
            byte[] e = new byte[myHash.GetDigestSize()];
            myHash.DoFinal (e, 0);

            BigInteger bigE = BigIntegerFromBytes(e);
            A = A.Multiply(bigE).Normalize();
            var y = A.YCoord.ToBigInteger().Negate();
            y = y.Mod(p);
            A = curve.Curve.CreatePoint(A.XCoord.ToBigInteger(),y).Normalize();
            A = A.Add(R).Normalize();
            return A.GetEncoded(true);
        }

        /// <summary>
        /// Computes the signature for an arbitrary message based on two private scalars:
        /// The one-time signing key and the oracle's private key
        /// </summary>       
        /// <param name="privateKey">The private key to sign with</param>
        /// <param name="oneTimeSigningKey">The one-time signing key to sign with</param>
        /// <param name="message">The message to sign</param>
        public static byte[] ComputeSignature(byte[] privKey, byte[] oneTimeSigningKey, byte[] message) {
            
            BigInteger bigPriv = BigIntegerFromBytes(privKey);
            BigInteger bigK = BigIntegerFromBytes(oneTimeSigningKey);

            ECPoint r = domain.G.Multiply(bigK).Normalize();
            byte[] rX = r.XCoord.ToBigInteger().ToByteArray();
            while(rX[0] == (byte)0) {
                rX = rX.Skip(1).ToArray();
            }

            Sha256Digest myHash = new Sha256Digest();
            myHash.BlockUpdate (message, 0, message.Length);
            myHash.BlockUpdate (rX, 0, rX.Length);
            byte[] e = new byte[myHash.GetDigestSize()];
            myHash.DoFinal (e, 0);

            BigInteger bigE = BigIntegerFromBytes(e);

            BigInteger bigS = bigE.Multiply(bigPriv);

            var bigS2 = bigK.Subtract(bigS);
            var bigS3 = bigS2.Mod(curve.N);
            byte[] sigBytes = StringToByteArray(BigIntegerToString(bigS3));
            byte[] signature = new byte[32];
            Array.Copy(sigBytes,0,signature,32-sigBytes.Length,sigBytes.Length);
            return signature;

        }

        private static string BigIntegerToString(BigInteger big) {
            var returnString = big.ToString(16);
            if(returnString.Length % 2 != 0) { returnString = "0" + returnString; }
            return returnString;
        }

        private static BigInteger BigIntegerFromBytes(byte[] bytes) {
            return new BigInteger(ByteArrayToString(bytes), 16);
        }
        private static string ByteArrayToString(byte[] bytes) {
            return BitConverter.ToString(bytes).Replace("-","");
        }

        private static byte[] StringToByteArray(string hex) {
            
                return Enumerable.Range(0, hex.Length)
                     .Where(x => x % 2 == 0)
                     .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                     .ToArray();
        }
    }
}
