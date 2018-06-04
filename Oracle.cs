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
    public static class Oracle
    {
        private static SecureRandom secureRandom = new SecureRandom ();
        private static X9ECParameters curve = SecNamedCurves.GetByName ("secp256k1");
        private static ECDomainParameters domain = new ECDomainParameters (curve.Curve, curve.G, curve.N, curve.H);

        private static BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
        
        public static byte[] GenerateNumericMessage(long value) {
            return StringToByteArray(value.ToString("x64"));
        }

        public static byte[] PublicKeyFromPrivateKey(byte[] privateKey) {
            BigInteger d = BigIntegerFromBytes(privateKey);

            ECPoint q = domain.G.Multiply(d).Normalize();
            return q.GetEncoded(true);
        }

        public static byte[] GenerateOneTimeSigningKey() {
            return secureRandom.GenerateSeed(32);
        }


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
