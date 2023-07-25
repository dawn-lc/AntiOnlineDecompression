using CSChaCha20;
using System;
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
        public static async Task VerifyHash(this Stream stream, byte[] hash)
        {
            Console.WriteLine("校验中...");
            byte[] streamHash = await stream.SHA256HashAsync();
            if (!streamHash.SequenceCompare(hash))
            {
                throw new Exception($"校验失败！{Environment.NewLine}(A)SHA256:{streamHash.BytesToHexString()}{Environment.NewLine}(B)SHA256:{hash.BytesToHexString()}");
            }
            Console.WriteLine("校验完成。");
        }
        public static byte[] RandomBytes(int length)
        {
            return RandomNumberGenerator.GetBytes(length);
        }
        public static byte[] StreamRead(this Stream stream, long a, long b)
        {
            if ((b - a) > int.MaxValue || stream.Length < 4)
            {
                throw new OverflowException();
            }
            long save = stream.Position;
            int DataLength = (int)(b - a);
            byte[] ReadData;
            stream.Seek(a, SeekOrigin.Begin);
            ReadData = stream.StreamRead(DataLength);
            stream.Seek(save, SeekOrigin.Begin);
            return ReadData;
        }
        public static byte[] StreamRead(this Stream stream, int length)
        {
            byte[] buffer = new byte[length];
            int offset = 0;
            int count = buffer.Length;
            int bytesRead;
            while (count > 0 && (bytesRead = stream.Read(buffer, offset, count)) > 0)
            {
                offset += bytesRead; // 增加偏移量
                count -= bytesRead; // 减少剩余字节数
            }
            return buffer;
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

        public static void CoverWrite(string s)
        {
            int oldX = Console.CursorLeft;
            int oldY = Console.CursorTop;
            Console.Write(s);
            Console.SetCursorPosition(oldX, oldY);
        }

        public static async Task Encrypto(this Stream data, Stream encrypted, byte[] key, byte[] iv)
        {
            int bytesRead;
            byte[] buffer = new byte[1024 * 1024 * 8];
            ChaCha20 Encrypto = new(key, iv, 0);
            while ((bytesRead = await data.ReadAsync(buffer)) != 0)
            {
                byte[] encryptedBuffer = new byte[bytesRead];
                Encrypto.EncryptBytes(encryptedBuffer, buffer.AsMemory(0, bytesRead).ToArray());
                await encrypted.WriteAsync(encryptedBuffer);
                CoverWrite($" {(data.Position / (double)data.Length) * 100:f2}%");
            }
        }
        public static async Task Decrypto(this Stream encrypted, Stream data, byte[] key, byte[] iv)
        {
            int bytesRead;
            byte[] buffer = new byte[1024 * 1024 * 4];
            ChaCha20 Decrypto = new(key, iv, 0);
            while ((bytesRead = await encrypted.ReadAsync(buffer)) != 0)
            {
                byte[] decryptedBuffer = new byte[bytesRead];
                Decrypto.DecryptBytes(decryptedBuffer, buffer.AsMemory(0, bytesRead).ToArray());
                await data.WriteAsync(decryptedBuffer);
                CoverWrite($" {(encrypted.Position / (double)encrypted.Length) * 100:f2}%");
            }
        }
    }
}
