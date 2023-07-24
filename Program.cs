using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using static AntiOnlineDecompression.ExtensionMethods;

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
                public required byte[] Hash { get; set; }
                public byte[] Serialize()
                {
                    MemoryStream data = new();
                    data.Write(IntToBytes(IV.Length));
                    data.Write(IV);
                    data.Write(IntToBytes(Hash.Length));
                    data.Write(Hash);
                    return data.ToArray();
                }
                internal static CryptoHead Deserialize(Stream stream)
                {
                    return new()
                    {
                        IV = stream.BytesRead(stream.BytesRead(4).BytesToInt()),
                        Hash = stream.BytesRead(stream.BytesRead(4).BytesToInt())
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
                    return new()
                    {
                        Key = stream.BytesRead(stream.BytesRead(4).BytesToInt()),
                        Hash = stream.BytesRead(stream.BytesRead(4).BytesToInt()),
                        Name = stream.BytesRead(stream.BytesRead(4).BytesToInt()).BytesToString()
                    };
                }
            }
            public static async Task Encrypto(Stream data, Stream cryptodata, byte[] key)
            {
                long SaveDataPosition = data.Position;
                cryptodata.SetLength(0);

                CryptoHead Head = new()
                {
                    IV = RandomBytes(12),
                    Hash = await data.SHA256HashAsync()
                };
                await cryptodata.WriteAsync(StringToBytes("AODF"));
                await cryptodata.WriteAsync(Head.Serialize());

                await data.Encrypto(cryptodata, key, Head.IV);

                data.Seek(SaveDataPosition, SeekOrigin.Begin);
                cryptodata.Seek(0, SeekOrigin.Begin);
            }
            public static async Task Decrypto(Stream cryptodata, Stream data, byte[] key)
            {
                long SaveCryptoDataPosition = cryptodata.Position;
                data.SetLength(0);

                cryptodata.Seek(4, SeekOrigin.Begin);
                CryptoHead FileHead = CryptoHead.Deserialize(cryptodata);

                await cryptodata.Decrypto(data, key, FileHead.IV);
                data.Seek(0, SeekOrigin.Begin);
                if (!(await data.SHA256HashAsync()).SequenceCompare(FileHead.Hash))
                {
                    throw new Exception("校验失败！");
                }

                cryptodata.Seek(SaveCryptoDataPosition, SeekOrigin.Begin);
                data.Seek(0, SeekOrigin.Begin);
            }
        }

        static async Task<int> Main(string[] args)
        {
            Console.CursorVisible = false;
            try
            {
                FileInfo? file;
                if (!args.Any())
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
                    if ( file == default(FileInfo?) || file is null )
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
                Crypto.CryptoKey cryptoKey;

                using FileStream InputFile = file.Open(FileMode.Open, FileAccess.Read);
                if (InputFile.StreamRead(0, 4).BytesToString() != "AODF")
                {
                    string EncryptFileName = Path.GetFileNameWithoutExtension(Path.GetRandomFileName());
                    string EncryptFileDirectoryName = file.DirectoryName ?? Environment.CurrentDirectory;

                    Console.Write("加密中...");
                    byte[] Key = RandomBytes(32);
                    using FileStream EncryptFile = new(Path.Combine(EncryptFileDirectoryName, EncryptFileName), FileMode.OpenOrCreate);
                    await Crypto.Encrypto(InputFile, EncryptFile, Key);
                    Console.WriteLine($" 100%   ");
                    cryptoKey = new()
                    {
                        Key = Key,
                        Hash = await EncryptFile.SHA256HashAsync(),
                        Name = file.Name
                    };
                    using (FileStream KeyFile = new($"{Path.Combine(EncryptFileDirectoryName, EncryptFileName)}.aodk", FileMode.Create))
                    {
                        KeyFile.SetLength(0);
                        await KeyFile.WriteAsync(StringToBytes("AODK"));
                        await KeyFile.WriteAsync(cryptoKey.Serialize());
                    }
                    Console.WriteLine("加密完成。");
                    return 0;
                }
                else if (File.Exists($"{file.FullName}.aodk"))
                {
                    using (FileStream KeyFile = new($"{file.FullName}.aodk", FileMode.Open))
                    {
                        try
                        {
                            if (KeyFile.StreamRead(0, 4).BytesToString() == "AODK")
                            {
                                KeyFile.Seek(4, SeekOrigin.Begin);
                            }
                            cryptoKey = Crypto.CryptoKey.Deserialize(KeyFile);
                        }
                        catch (Exception)
                        {
                            throw new Exception("解密密钥格式错误！");
                        }
                    }
                    Console.WriteLine("校验文件中...");
                    byte[] EncryptFileHash = await InputFile.SHA256HashAsync();
                    if (!EncryptFileHash.SequenceCompare(cryptoKey.Hash))
                    {
                        throw new Exception($"加密文件校验失败！SHA256:{EncryptFileHash.BytesToHexString()}");
                    }
                    Console.Write("解密中...");
                    using FileStream DecryptFile = new(cryptoKey.Name, FileMode.Create);
                    await Crypto.Decrypto(InputFile, DecryptFile, cryptoKey.Key);
                    Console.WriteLine($" 100%   ");
                    Console.WriteLine("解密完成。");
                    return 0;
                }
                throw new Exception("未找到任何可用的文件");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.ReadKey();
                return 1;
            }
        }
    }
}
