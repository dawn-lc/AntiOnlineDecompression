# AntiOnlineDecompression

AntiOnlineDecompression 是一个开源工具，旨在防止各类网盘的在线解压功能导致文件内容信息泄露。

## 功能

- **文件加密**：采用 ChaCha20 加密算法，采用了加密文件与解密密钥分离的设计，确保文件在传输和存储过程中的安全性。

- **文件解密**：将加密文件和解密密钥置于同一文件夹中，启动工具，工具会自动查找解密密钥并进行解密。

## 开始

* GitHub Release
 **[下载](https://github.com/dawn-lc/AntiOnlineDecompression/releases/download/latest/AntiOnlineDecompression.exe)**

* 从源码编译

本工具基于 .NET 9 AOT（Ahead Of Time）编译。请确保您的系统已安装 .NET 9 运行时环境。

1. 从 [GitHub 仓库](https://github.com/dawn-lc/AntiOnlineDecompression) 克隆或下载最新版本的代码。

2. 在项目根目录下，使用以下命令编译项目：

   ```bash
   dotnet publish -c Release -r win-x64
   ```

3. 在生成的发布文件夹中，找到可执行文件 `AntiOnlineDecompression.exe`，即可开始使用。

## 使用说明

### 加密文件

1. 将需要加密的文件使用本工具打开。

工具将生成两个文件：加密后的文件、解密密钥文件。

### 解密文件

1. 确保加密文件和对应的解密密钥文件以及本工具位于同一文件夹中。

2. 运行本工具

工具将自动查找解密密钥并进行解密。

## 注意事项

- 请勿在共享加密文件时，将解密密钥一同上传至不安全的网盘。

- 建议通过其他安全手段（如加密的电子邮件或安全的消息传递应用）共享解密密钥。

- 推荐使用各类压缩软件将文件或文件夹进行压缩打包后再使用本工具进行加密。

- 推荐将加密后的文件与本工具一起发布，将解密密钥单独发布。
