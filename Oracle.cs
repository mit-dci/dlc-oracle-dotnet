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
            BigInteger d = new BigInteger(privateKey);

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

             Console.WriteLine("rX: {0} {1}", R.XCoord.ToBigInteger().SignValue, BitConverter.ToString(rX).Replace("-",""));


            Sha256Digest myHash = new Sha256Digest();
            myHash.BlockUpdate (message, 0, message.Length);
            myHash.BlockUpdate (rX, 0, rX.Length);
            byte[] e = new byte[myHash.GetDigestSize()];
            myHash.DoFinal (e, 0);

            BigInteger bigE = BigIntegerFromBytes(e);
            Console.WriteLine("bigE: {0} {1}", bigE.SignValue, BigIntegerToString(bigE));

            A = A.Multiply(bigE);
            Console.WriteLine("A.Y (1): {0} {1}", A.YCoord.ToBigInteger().SignValue, BigIntegerToString(A.YCoord.ToBigInteger()));

            var y = A.YCoord.ToBigInteger().Negate();
            Console.WriteLine("A.Y (2): {0} {1}", y.SignValue, BigIntegerToString(y));
            y = y.Mod(p);
            
            Console.WriteLine("A.Y (3): {0} {1}", y.SignValue, BigIntegerToString(y));
            A = curve.Curve.CreatePoint(A.XCoord.ToBigInteger(),y);
            A = A.Add(R);
            return A.GetEncoded(true);
        }

        public static byte[] ComputeSignature(byte[] privKey, byte[] oneTimeSigningKey, byte[] message) {
            
            BigInteger bigPriv = BigIntegerFromBytes(privKey);
            BigInteger bigK = BigIntegerFromBytes(oneTimeSigningKey);
            Console.WriteLine("bigPriv: {0} {1}", bigPriv.SignValue, BigIntegerToString(bigPriv));
            Console.WriteLine("bigK: {0} {1}", bigK.SignValue, BigIntegerToString(bigK));

            ECPoint r = domain.G.Multiply(bigK).Normalize();
            byte[] rX = r.XCoord.ToBigInteger().ToByteArray();
            while(rX[0] == (byte)0) {
                rX = rX.Skip(1).ToArray();
            }
            
            Console.WriteLine("rX: {0} {1}", r.XCoord.ToBigInteger().SignValue, BitConverter.ToString(rX).Replace("-",""));

            Sha256Digest myHash = new Sha256Digest();
            myHash.BlockUpdate (message, 0, message.Length);
            myHash.BlockUpdate (rX, 0, rX.Length);
            byte[] e = new byte[myHash.GetDigestSize()];
            myHash.DoFinal (e, 0);

            BigInteger bigE = BigIntegerFromBytes(e);
            Console.WriteLine("bigE: {0} {1}", bigE.SignValue, BigIntegerToString(bigE));

            BigInteger bigS = bigE.Multiply(bigPriv);
            Console.WriteLine("bigS(1): {0} {1}", bigS.SignValue, BigIntegerToString(bigS));

            Console.WriteLine("bigK: {0} {1}", bigK.SignValue, BigIntegerToString(bigK));
            var bigS2 = bigK.Subtract(bigS);
            Console.WriteLine("bigS(2): {0} {1}", bigS2.SignValue, BigIntegerToString(bigS2));
            var bigS3 = bigS2.Mod(curve.N);
            Console.WriteLine("bigS(3): {0} {1}", bigS3.SignValue, BigIntegerToString(bigS3));
            return StringToByteArray(BigIntegerToString(bigS3));
        }

        private static string BigIntegerToString(BigInteger big) {
            return big.ToString(16);
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
