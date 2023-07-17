using CSChaCha20;
using System;
using System.Collections;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;


namespace AntiOnlineDecompression
{
    public static class ExtensionMethods
    {
        private static readonly SHA256 SHA256 = SHA256.Create();
        /// <summary>
        /// 计算SHA256Hash
        /// </summary>
        /// <param name="inputStream">数据流</param>
        /// <returns>SHA256Hash字节数组</returns>
        public static async Task<byte[]> SHA256HashAsync(this Stream inputStream)
        {
            long save = inputStream.Position;
            byte[] SHA256Hash = await SHA256.ComputeHashAsync(inputStream);
            inputStream.Seek(save, SeekOrigin.Begin);
            return SHA256Hash;
        }
        /// <summary>
        /// 计算SHA256Hash
        /// </summary>
        /// <param name="inputBytes">数据</param>
        /// <returns>SHA256Hash字节数组</returns>
        public static byte[] SHA256Hash(this byte[] inputBytes)
        {
            return SHA256.ComputeHash(inputBytes);
        }
        /// <summary>
        /// 字节数组转16进制字符串
        /// </summary>
        /// <param name="byteDatas"></param>
        /// <returns></returns>
        public static string BytesToHexString(this byte[] byteDatas)
        {
            StringBuilder builder = new();
            for (int i = 0; i < byteDatas.Length; i++)
            {
                builder.Append(string.Format("{0:X2}", byteDatas[i]));
            }
            return builder.ToString();
        }
        /// <summary>
        /// 16进制字符串转字节数组
        /// </summary>
        /// <param name="HexString"></param>
        /// <returns></returns>
        public static byte[] HexStringToBytes(this string HexString)
        {
            if (HexString.Length % 2 != 0) throw new ArgumentException("Format err", nameof(HexString));
            char[] Hex = HexString.ToCharArray();
            byte[] bytes = new byte[Hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte($"{Hex[i * 2]}{Hex[(i * 2) + 1]}", 16);
            }
            return bytes;
        }
        /// <summary>
        /// 字节数组是否相等
        /// </summary>
        /// <param name="byteDatas"></param>
        /// <returns></returns>
        public static bool SequenceCompare(this byte[]? a, byte[]? b)
        {
            if (ReferenceEquals(a, b)) return true;
            if (a is null || b is null) return false;
            if (a.Length != b.Length) return false;
            return a.SequenceEqual(b);
        }

        /// <summary>
        /// byte[] 不同计数
        /// </summary>
        /// <param name="byteDatas"></param>
        /// <returns></returns>
        public static int Differences(this byte[] a, byte[] b)
        {
            return new BitArray(a).Differences(new BitArray(b));
        }
        /// <summary>
        /// BitArray 不同计数
        /// </summary>
        /// <param name="byteDatas"></param>
        /// <returns></returns>
        public static int Differences(this BitArray a, BitArray b)
        {
            int differences = 0;
            BitArray xor = a.Xor(b);
            for (int i = 0; i < xor.Length; i++)
            {
                if (xor[i])
                {
                    differences++;
                }
            }
            return differences;
        }
        public static byte[] RandomBytes(int length)
        {
            return RandomNumberGenerator.GetBytes(length);
        }
        public static byte[] StreamRead(this Stream stream, long a, long b)
        {
            if ((b - a) > int.MaxValue)
            {
                throw new OverflowException();
            }
            long save = stream.Position;
            int DataLength = (int)(b - a);
            byte[] ReadData = new byte[DataLength];
            stream.Seek(a, SeekOrigin.Begin);
            stream.Read(ReadData, 0, DataLength);
            stream.Seek(save, SeekOrigin.Begin);
            return ReadData;
        }
        public static byte[] BytesRead(this byte[] bytes, ref int pos, int length)
        {
            int p = pos;
            pos += length;
            return bytes[p..(p + length)];
        }

        public static byte[] StringToBytes(string value)
        {
            return Encoding.UTF8.GetBytes(value);
        }
        public static byte[] IntToBytes(int value)
        {
            byte[] bytes = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }
            return bytes;
        }
        public static string BytesToString(this byte[] value)
        {
            return Encoding.UTF8.GetString(value);
        }
        public static int BytesToInt(this byte[] value)
        {
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(value);
            }
            return BitConverter.ToInt32(value);
        }

        public static async Task Encrypto(this Stream data, Stream encrypted, byte[] key, byte[] iv)
        {
            int bytesRead;
            byte[] buffer = new byte[102400000];
            ChaCha20 Encrypto = new(key, iv, 0);
            while ((bytesRead = await data.ReadAsync(buffer)) != 0)
            {
                byte[] encryptedBuffer = new byte[bytesRead];
                Encrypto.EncryptBytes(encryptedBuffer, buffer.AsMemory(0, bytesRead).ToArray());
                await encrypted.WriteAsync(encryptedBuffer);

            }
        }
        public static async Task Decrypto(this Stream encrypted, Stream data, byte[] key, byte[] iv)
        {
            int bytesRead;
            byte[] buffer = new byte[102400000];
            ChaCha20 Decrypto = new(key, iv, 0);
            while ((bytesRead = await encrypted.ReadAsync(buffer)) != 0)
            {
                byte[] decryptedBuffer = new byte[bytesRead];
                Decrypto.DecryptBytes(decryptedBuffer, buffer.AsMemory(0, bytesRead).ToArray());
                await data.WriteAsync(decryptedBuffer);
            }
        }
    }
}
