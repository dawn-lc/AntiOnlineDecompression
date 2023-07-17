using System;
using System.IO;
using System.Threading.Tasks;
using System.Linq;
using System.Collections.Generic;
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
                    List<byte> data = new();
                    data.AddRange(IntToBytes(IV.Length));
                    data.AddRange(IV);
                    data.AddRange(IntToBytes(Hash.Length));
                    data.AddRange(Hash);
                    return data.ToArray();
                }

                internal static CryptoHead Deserialize(byte[] bytes)
                {
                    int pos = 0;
                    return new CryptoHead()
                    {
                        IV = bytes.BytesRead(ref pos, bytes.BytesRead(ref pos, 4).BytesToInt()),
                        Hash = bytes.BytesRead(ref pos, bytes.BytesRead(ref pos, 4).BytesToInt())
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
                    List<byte> data = new();
                    data.AddRange(IntToBytes(Key.Length));
                    data.AddRange(Key);
                    data.AddRange(IntToBytes(Hash.Length));
                    data.AddRange(Hash);
                    data.AddRange(IntToBytes(StringToBytes(Name).Length));
                    data.AddRange(StringToBytes(Name));
                    return data.ToArray();
                }
                internal static CryptoKey Deserialize(byte[] bytes)
                {
                    int pos = 0;
                    return new()
                    {
                        Key = bytes.BytesRead(ref pos, bytes.BytesRead(ref pos, 4).BytesToInt()),
                        Hash = bytes.BytesRead(ref pos, bytes.BytesRead(ref pos, 4).BytesToInt()),
                        Name = bytes.BytesRead(ref pos, bytes.BytesRead(ref pos, 4).BytesToInt()).BytesToString()
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
                byte[] HeadBytes = Head.Serialize();
                await cryptodata.WriteAsync(StringToBytes("AODF"));
                await cryptodata.WriteAsync(IntToBytes(HeadBytes.Length));
                await cryptodata.WriteAsync(HeadBytes);

                await data.Encrypto(cryptodata, key, Head.IV);

                data.Seek(SaveDataPosition, SeekOrigin.Begin);
                cryptodata.Seek(0, SeekOrigin.Begin);
            }
            public static async Task Decrypto(Stream cryptodata, Stream data, byte[] key)
            {
                long SaveCryptoDataPosition = cryptodata.Position;
                data.SetLength(0);

                int HeadLength = cryptodata.StreamRead(4, 8).BytesToInt();
                CryptoHead FileHead = CryptoHead.Deserialize(cryptodata.StreamRead(8, 8 + HeadLength));
                cryptodata.Seek(8 + HeadLength, SeekOrigin.Begin);
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
            try
            {
                FileInfo? file;
                if (!args.Any())
                {
                    IEnumerable<FileInfo> fileInfos = new DirectoryInfo(Environment.CurrentDirectory).GetFiles().Where(i => i.FullName != Environment.ProcessPath);
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
                    if (!fileInfos.Any() || fileInfos.Count() < 2 || file == null)
                    {
                        throw new FileNotFoundException($"待解密文件不存在或无法访问！");
                    }
                }
                else
                {
                    file = new FileInfo(args[0].Replace("\"", ""));
                }
                if (!file.Exists)
                {
                    throw new FileNotFoundException(args[0]);
                }
                Crypto.CryptoKey cryptoKey;

                using FileStream InputFile = file.Open(FileMode.Open, FileAccess.Read);
                if (InputFile.StreamRead(0, 4).BytesToString() != "AODF")
                {
                    byte[] Key = RandomBytes(32);
                    string EncryptoFileName;
                    EncryptoFileName = (await InputFile.SHA256HashAsync()).BytesToHexString();
                    using FileStream EncryptFile = new($"{EncryptoFileName}", FileMode.OpenOrCreate);
                    await Crypto.Encrypto(InputFile, EncryptFile, Key);
                    cryptoKey = new()
                    {
                        Key = Key,
                        Hash = await EncryptFile.SHA256HashAsync(),
                        Name = file.Name
                    };
                    using (FileStream KeyFile = new($"{EncryptoFileName}.key", FileMode.Create))
                    {
                        KeyFile.SetLength(0);
                        await KeyFile.WriteAsync(cryptoKey.Serialize());
                    }
                    Console.WriteLine("加密完成。");
                    return 0;
                }
                else
                {
                    if (!File.Exists($"{file.FullName}.key"))
                    {
                        throw new FileNotFoundException($"解密密钥 {file.FullName}.key 不存在或无法访问！");
                    }
                    using (FileStream KeyFile = new($"{file.FullName}.key", FileMode.Open))
                    {
                        cryptoKey = Crypto.CryptoKey.Deserialize(KeyFile.StreamRead(0, KeyFile.Length));
                    }
                    byte[] EncryptFileHash = await InputFile.SHA256HashAsync();
                    if (!EncryptFileHash.SequenceCompare(cryptoKey.Hash))
                    {
                        throw new Exception($"加密文件校验失败！SHA256:{EncryptFileHash.BytesToHexString()}");
                    }
                    using FileStream DecryptFile = new(cryptoKey.Name, FileMode.Create);
                    await Crypto.Decrypto(InputFile, DecryptFile, cryptoKey.Key);
                    Console.WriteLine("解密完成。");
                    return 0;
                }
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
