using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using static AntiOnlineDecompression.ExtensionMethods;
using static AntiOnlineDecompression.Program.Crypto;

namespace AntiOnlineDecompression
{
    class Program
    {
        interface IBinaryObject
        {
            public byte[] Serialize();
        }
        public static class Crypto
        {
            public class CryptoHead : IBinaryObject
            {
                public required byte[] IV { get; set; }
                public byte[] Serialize()
                {
                    MemoryStream data = new();
                    data.Write(StringToBytes("AODF"));
                    data.Write(IntToBytes(IV.Length));
                    data.Write(IV);
                    return data.ToArray();
                }
                internal static CryptoHead Deserialize(Stream stream)
                {
                    stream.Seek(4, SeekOrigin.Begin);
                    return new()
                    {
                        IV = stream.StreamRead(stream.StreamRead(4).BytesToInt())
                    };
                }
            }
            public class CryptoKey : IBinaryObject
            {
                public required byte[] Key { get; set; }
                public required byte[] Hash { get; set; }
                public required string Name { get; set; }
                public byte[] Serialize()
                {
                    MemoryStream data = new();
                    data.Write(StringToBytes("AODK"));
                    data.Write(IntToBytes(Key.Length));
                    data.Write(Key);
                    data.Write(IntToBytes(Hash.Length));
                    data.Write(Hash);
                    data.Write(IntToBytes(StringToBytes(Name).Length));
                    data.Write(StringToBytes(Name));
                    return data.ToArray();
                }
                internal static CryptoKey Deserialize(Stream stream)
                {
                    if (stream.StreamRead(0, 4).BytesToString() == "AODK")
                    {
                        stream.Seek(4, SeekOrigin.Begin);
                    }
                    return new()
                    {
                        Key = stream.StreamRead(stream.StreamRead(4).BytesToInt()),
                        Hash = stream.StreamRead(stream.StreamRead(4).BytesToInt()),
                        Name = stream.StreamRead(stream.StreamRead(4).BytesToInt()).BytesToString()
                    };
                }
            }
            public static async Task Encrypto(Stream data, Stream cryptodata, byte[] key)
            {
                Console.Write("加密中...");
                Stopwatch stopwatch = new();
                stopwatch.Restart();
                long SaveDataPosition = data.Position;
                cryptodata.SetLength(0);

                CryptoHead Head = new()
                {
                    IV = RandomBytes(12)
                };
                await cryptodata.WriteAsync(Head.Serialize());

                await data.Encrypto(cryptodata, key, Head.IV);
                cryptodata.Seek(0, SeekOrigin.Begin);

                data.Seek(SaveDataPosition, SeekOrigin.Begin);
                stopwatch.Stop();
                Console.WriteLine();
                Console.WriteLine($"加密完成。耗时{ stopwatch.Elapsed.TimeFormat() }");
            }
            public static async Task Decrypto(Stream cryptodata, Stream data, byte[] key)
            {
                Console.Write("解密中...");
                Stopwatch stopwatch = new();
                stopwatch.Restart();
                long SaveCryptoDataPosition = cryptodata.Position;
                data.SetLength(0);

                CryptoHead FileHead = CryptoHead.Deserialize(cryptodata);

                await cryptodata.Decrypto(data, key, FileHead.IV);
                data.Seek(0, SeekOrigin.Begin);

                cryptodata.Seek(SaveCryptoDataPosition, SeekOrigin.Begin);
                stopwatch.Stop();
                Console.WriteLine();
                Console.WriteLine($"解密完成。耗时{ stopwatch.Elapsed.TimeFormat() }");
            }
        }
        public static void WriteCryptoKey(string filePath, CryptoKey key)
        {
            if (File.Exists(filePath))
            {
                throw new Exception($"{filePath}已存在！");
            }
            using FileStream KeyFile = new(filePath, FileMode.OpenOrCreate);
            KeyFile.Write(key.Serialize());
        }
        public static CryptoKey ReadCryptoKey(string? keyFilePath)
        {
            while (!File.Exists(keyFilePath))
            {
                Console.Write("解密密钥未找到，请提供解密密钥！请输入解密密钥路径:");
                keyFilePath = (Console.ReadLine() ?? "").Replace("\"", "");
            }
            using FileStream KeyFile = new(keyFilePath, FileMode.Open);
            try
            {
                return CryptoKey.Deserialize(KeyFile);
            }
            catch (Exception)
            {
                throw new Exception("解密密钥格式错误！");
            }
            finally
            {
                KeyFile.Dispose();
            }
        }
        public static string RandomFileName()
        {
            return Path.GetFileNameWithoutExtension(Path.GetRandomFileName());
        }

        static async Task<int> Main(string[] args)
        {
            Console.CursorVisible = false;
            try
            {
                FileInfo? file;
                if (args.Length == 0)
                {
                    FileInfo[] fileInfos = new DirectoryInfo(Environment.CurrentDirectory).GetFiles();
                    fileInfos = fileInfos.Where(i => i.FullName != Environment.ProcessPath).ToArray();
                    if (fileInfos.Length < 2)
                    {
                        throw new Exception($"未找到需要解密的文件！");
                    }
                    file = fileInfos.FirstOrDefault(i =>
                    {
                        FileStream? stream = null;
                        try
                        {
                            stream = i.Open(FileMode.Open, FileAccess.Read, FileShare.Read);
                            return stream.StreamRead(0, 4).BytesToString() == "AODF";
                        }
                        catch (Exception)
                        {
                            return false;
                        }
                        finally
                        {
                            stream?.Dispose();
                        }
                    });
                    if (file == default(FileInfo?) || file is null)
                    {
                        throw new Exception($"在检索程序目录下可能需要解密的文件时，未找到符合条件的文件或文件无法访问！");
                    }
                }
                else
                {
                    file = new FileInfo(args[0].Replace("\"", ""));
                }
                if (!file.Exists)
                {
                    throw new Exception(args[0]);
                }

                CryptoKey cryptoKey;

                using FileStream InputFile = file.Open(FileMode.Open, FileAccess.Read);

                switch (InputFile.StreamRead(0, 4).BytesToString())
                {
                    case "AODF":
                        cryptoKey = ReadCryptoKey($"{file.FullName}.aodk");

                        await InputFile.VerifyHash(cryptoKey.Hash);

                        using (FileStream DecryptFile = new(cryptoKey.Name, FileMode.Create))
                        {
                            await Decrypto(InputFile, DecryptFile, cryptoKey.Key);
                        }
                        break;
                    default:
                        string EncryptFilePath = Path.Combine(file.DirectoryName ?? Environment.CurrentDirectory, RandomFileName());
                        while (File.Exists(EncryptFilePath))
                        {
                            EncryptFilePath = Path.Combine(file.DirectoryName ?? Environment.CurrentDirectory, RandomFileName());
                        }
                        byte[] Key = RandomBytes(32);
                        byte[] EncryptFileHash;
                        using (FileStream EncryptFile = new(EncryptFilePath, FileMode.OpenOrCreate))
                        {
                            Stopwatch stopwatch = new();
                            stopwatch.Restart();
                            await Encrypto(InputFile, EncryptFile, Key);
                            Console.WriteLine("创建校验记录中...");
                            EncryptFileHash = await EncryptFile.SHA256HashAsync();
                            stopwatch.Stop();
                            Console.WriteLine($"创建校验记录完成。耗时{stopwatch.Elapsed.TimeFormat()}");
                        }
                        cryptoKey = new()
                        {
                            Key = Key,
                            Name = file.Name,
                            Hash = EncryptFileHash
                        };
                        WriteCryptoKey($"{EncryptFilePath}.aodk", cryptoKey);
                        break;
                }
                Console.ReadKey();
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                    Console.ReadKey();
                return 1;
            }
            finally
            {
                Console.CursorVisible = true;
            }
        }
    }
}
