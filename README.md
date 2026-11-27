# 密码工具箱

密码工具箱是一个 Windows 64 位桌面应用。左侧输入文本，右侧查看并复制加密、解密或摘要结果。所有密码运算都在本机执行。只有手动检查或下载更新时，应用才会连接 GitHub。

## 安装与使用

从 [GitHub Releases](https://github.com/ttbsdj/cryptography-toolbox/releases/latest) 下载 `Cryptography-Toolbox-Setup-<版本>.exe`，运行安装程序。

| 算法 | 支持的操作 | 密钥 |
| --- | --- | --- |
| AES-GCM | 加密、解密 | 密码，或 16、24、32 字节密钥 |
| AES-CBC | 加密、解密 | 密码，或 16、24、32 字节密钥 |
| SM4-CBC | 加密、解密 | 密码，或 16 字节密钥 |
| SM3 | 计算、校验摘要 | 无 |

- **加密或解密**。选择算法和操作，填入密钥，再点击处理按钮。加密输入和解密输出采用 UTF-8 文本。密文支持 Base64 和 Hex。
- **密文包**。默认模式。密文包包含随机生成的 IV、用于密码派生的盐值（如适用）以及认证数据。解密时选择相同的算法、密钥类型和编码，并输入对应的密码或密钥。
- **原始密文**。用于和其他软件交换数据。密钥支持 Hex 和 Base64。CBC 使用 PKCS#7 填充和 16 字节 IV。AES-GCM 使用 12 字节 IV 和 16 字节认证标签。IV 和标签按 Hex 单独输入或复制。原始 CBC 密文没有内置认证。
- **SM3 摘要**。选择“计算摘要”时可导出 Hex 或 Base64 摘要。选择“校验摘要”时，在原文之外输入已知摘要，应用会报告是否匹配。SM3 是单向哈希，摘要无法解密。
- 单次处理支持最多 1 MiB 的 UTF-8 原文。

## 软件内更新

在已安装的应用中打开右上角的更新面板并检查更新。找到新版本后，点击下载，然后选择安装并重启。应用从 GitHub Releases 读取更新清单，下载后会按清单核对文件的 SHA-512。第一版安装程序未使用 Windows Authenticode 签名。

## 本地开发

使用 Node.js 24 或更新版本。在 PowerShell 中运行以下命令。

```powershell
npm.cmd ci
npm.cmd test
npm.cmd start
```

运行 `npm.cmd run dist:win` 生成 Windows x64 安装包。输出位于 `dist/`。有 GitHub `origin` 时，打包会将该仓库作为更新源。也可在打包前将 `GITHUB_REPOSITORY` 设置为目标公开仓库的 `owner/repo`。

## 发布新版本

修改版本号并提交后，推送与版本号匹配的正式标签，例如 `v0.1.1`。GitHub Actions 会运行测试、打包，并把安装程序、`.blockmap` 与 `latest.yml` 发布到同一个 GitHub Release。已安装的客户端使用这些文件检查并安装新版本。
