# dpass [![License](https://img.shields.io/badge/license-BSD%202--Clause-green.svg)](https://opensource.org/licenses/BSD-2-Clause) [![Build Status](https://github.com/rbee3u/dpass/actions/workflows/build.yml/badge.svg)](https://github.com/rbee3u/dpass/actions?query=branch%3Amain)

[English](README.md) | 简体中文 | [繁體中文](README.zh-TW.md)

`dpass` 是一个命令行工具，用于通过基于阈值的 Shamir 拆分与恢复来保护敏感数据，并可选地结合加密使用。它可以先对数据加密，再将其拆分为多个份额；之后再组合足够数量的份额恢复原始数据，并在需要时解密。

一个常见的使用场景是保护加密货币钱包助记词。针对这一工作流，`dpass` 提供了面向钱包的辅助能力，可用于生成 BIP-39 助记词、为多条链派生地址或私钥，并将可导入结果渲染为终端二维码。

## 功能特性

- 使用可选的 AES-256-GCM 加密保护任意标准输入数据。
- 将明文或密文拆分为基于阈值的 Shamir 份额。
- 通过组合份额恢复受保护数据，并在适用时对结果解密。
- 为钱包工作流生成 BIP-39 助记词。
- 从助记词派生 Bitcoin、Ethereum、Tron、Solana、Dogecoin 和 Sui 的地址或私钥。
- 将地址、私钥或其他载荷渲染为终端二维码。

## 安装

```shell
go install github.com/rbee3u/dpass@latest
```

## 命令概览

- `encrypt` / `decrypt`：使用基于密码派生的密钥，通过 AES-256-GCM 对标准输入进行加密或解密。
- `split` / `combine`：将标准输入拆分为 PEM 编码的 Shamir 份额，或从标准输入读取份额并恢复原始数据。
- `mnemonic`：生成随机的 BIP-39 助记词。
- `bitcoin`、`ethereum`、`tron`、`solana`、`dogecoin`、`sui`：从标准输入读取助记词，并派生对应链的地址或私钥。
- `qrcode`：将标准输入渲染为终端二维码。
- `completion`：生成 shell 自动补全脚本。

使用 `dpass --help` 查看顶层命令列表，使用 `dpass <command> --help` 查看特定命令的参数说明。

大多数命令都从标准输入读取数据，并将结果写到标准输出，因此可以自然地通过管道组合。

## 工作流程

一个典型的保护与恢复流程如下：

1. 准备你想保护的敏感信息。
2. 可选地使用 `dpass encrypt` 对其加密。
3. 使用 `dpass split` 拆分明文或密文。
4. 将生成的份额分别存放在不同位置。
5. 收集足够数量、满足阈值要求的份额。
6. 使用 `dpass combine` 恢复数据。
7. 如果恢复出的数据是密文，再使用 `dpass decrypt` 解密。

当 `split` 配合 `-o <prefix>` 使用时，输出文件会写为 `<prefix>-<parts>-<threshold>-<index>.txt`。

下面的示例遵循这一流程，并且可以直接复制执行。

## 使用示例

### 保护任意敏感信息

先加密再拆分：

```shell
printf '%s' 'my sensitive data' | dpass encrypt | dpass split -o secret -n 5 -m 3
```

如果不需要加密，也可以直接拆分明文：

```shell
printf '%s' 'my sensitive data' | dpass split -o secret -n 5 -m 3
```

从任意满足阈值的份额集合中恢复加密数据，并对其解密：

```shell
cat secret-5-3-0.txt secret-5-3-1.txt secret-5-3-2.txt | dpass combine | dpass decrypt
```

恢复未加密直接拆分的明文：

```shell
cat secret-5-3-0.txt secret-5-3-1.txt secret-5-3-2.txt | dpass combine
```

### 保护钱包助记词

生成助记词、加密，并将密文拆分为 9 份，其中阈值为 4：

```shell
dpass mnemonic | dpass encrypt | dpass split -o wallet-cold -n 9 -m 4
```

恢复助记词，派生 Bitcoin 地址，并将其渲染为二维码：

```shell
cat wallet-cold-9-4-0.txt wallet-cold-9-4-1.txt wallet-cold-9-4-2.txt wallet-cold-9-4-3.txt | \
  dpass combine | dpass decrypt | dpass bitcoin | dpass qrcode
```

恢复助记词，派生 Bitcoin 私钥（WIF），并将其渲染为二维码：

```shell
cat wallet-cold-9-4-0.txt wallet-cold-9-4-1.txt wallet-cold-9-4-2.txt wallet-cold-9-4-3.txt | \
  dpass combine | dpass decrypt | dpass bitcoin --secret | dpass qrcode
```

恢复助记词并派生 Ethereum 地址：

```shell
cat wallet-cold-9-4-0.txt wallet-cold-9-4-1.txt wallet-cold-9-4-2.txt wallet-cold-9-4-3.txt | \
  dpass combine | dpass decrypt | dpass ethereum
```

## Shell 自动补全

`dpass` 可以为多种 shell 生成自动补全脚本。下面分别展示当前会话加载方式和持久安装方式。

### Zsh

```shell
# 安装一次
dpass completion zsh > "${fpath[1]}/_dpass"
```

### Bash

```shell
# 在当前会话中加载
source <(dpass completion bash)

# 在 Linux 上安装一次
dpass completion bash > /etc/bash_completion.d/dpass

# 在使用 Homebrew 的 macOS 上安装一次
dpass completion bash > "$(brew --prefix)/etc/bash_completion.d/dpass"
```

### Fish

```shell
# 在当前会话中加载
dpass completion fish | source

# 安装一次
dpass completion fish > ~/.config/fish/completions/dpass.fish
```

### PowerShell

```shell
# 在当前会话中加载
dpass completion powershell | Out-String | Invoke-Expression

# 安装一次
dpass completion powershell > "$HOME/dpass.ps1"
# 然后把这一行加入你的 PowerShell 配置文件 ($PROFILE)：
. "$HOME/dpass.ps1"
```
