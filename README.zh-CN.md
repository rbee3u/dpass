# dpass [![License](https://img.shields.io/badge/license-BSD%202--Clause-green.svg)](https://opensource.org/licenses/BSD-2-Clause) [![Build Status](https://github.com/rbee3u/dpass/actions/workflows/build.yml/badge.svg)](https://github.com/rbee3u/dpass/actions?query=branch%3Amain)

[English](README.md) | 简体中文 | [繁體中文](README.zh-TW.md)

`dpass` 是一款命令行工具，用阈值化的 Shamir 拆分与恢复来保护敏感数据，并可选配一层加密。流程很直接：需要时先加密，再把结果拆成多份分片；日后凑齐足够数量的分片就能恢复原始数据，必要时再解密回来。

它最常见的用途是保管加密货币钱包的助记词。围绕这一场景，`dpass` 内置了一组钱包小工具，可以生成 BIP-39 助记词、为多条链派生地址或私钥，并把可导入的结果直接渲染成终端二维码。

## 为什么会有 dpass

对一部分人来说，加密货币最看重的从来不是炒作，而是它的可携带性和自托管属性。一旦遭遇危机、被迫迁徙，或者当地体系不再可靠时，能跨境带走的数字资产，也许就是少数仍掌握在自己手里的财产形式。但资产可以随身带走，也带来了新的麻烦：助记词或私钥到底要怎么保管，才能既不把控制权交给别人，又不至于把安全全押在一个单点上？

`dpass` 给出的答案很朴素：

- 干脆放在交易所行不行？那等于把托管权重新交回给机构。既然目标是自己说了算，交易所就不该是最终归宿。
- 直接抄在纸上呢？孤零零的一份实体副本，被偷、损坏或遗失只是时间问题。
- 那放进云盘或密码管理器？这类服务照样可能泄密、把你锁在门外，或者悄无声息地变成新的单点。
- 这个项目主张怎么做？先把助记词或私钥加密，再拆成需要达到阈值才能恢复的若干分片，分散保管，同时保留必要的冗余。

这正是 `dpass` 想要支持的工作流。

## 功能特性

- 可选配 AES-256-GCM，对来自标准输入的任意数据加密保护。
- 把明文或密文按阈值拆分成 Shamir 分片。
- 凑齐分片即可恢复受保护的数据，必要时一并解密。
- 为钱包场景生成 BIP-39 助记词。
- 从助记词派生 Bitcoin、Ethereum、Tron、Solana、Dogecoin、Sui 的地址或私钥。
- 把地址、私钥或其他载荷渲染成终端二维码。

## 安装

```shell
go install github.com/rbee3u/dpass@v1.6.0
```

## 命令概览

- `encrypt` / `decrypt`：用口令派生出的密钥，对标准输入做 AES-256-GCM 加解密。
- `split` / `combine`：把标准输入拆成 PEM 编码的 Shamir 分片，或反过来从标准输入读取分片、还原出原始数据。
- `mnemonic`：生成一段随机的 BIP-39 助记词。
- `bitcoin`、`ethereum`、`tron`、`solana`、`dogecoin`、`sui`：从标准输入读取助记词，并派生对应链的地址或私钥。
- `qrcode`：把标准输入渲染为终端二维码。
- `completion`：生成 shell 自动补全脚本。

`dpass --help` 列出全部顶层命令，`dpass <command> --help` 则给出单个命令的参数说明。

多数命令都从标准输入读、向标准输出写，天然适合用管道串起来。

## 工作流程

一个典型的保护与恢复流程是这样的：

1. 准备好你想要保护的敏感信息。
2. 如果需要额外一层防护，用 `dpass encrypt` 把它加密。
3. 用 `dpass split` 把明文或密文拆成分片。
4. 把每份分片分别存放在不同位置。
5. 日后凑齐数量达到阈值的分片。
6. 用 `dpass combine` 还原数据。
7. 如果还原出来的是密文，再用 `dpass decrypt` 解密。

`split` 搭配 `-o <prefix>` 时，输出文件命名为 `<prefix>-<parts>-<threshold>-<index>.txt`。

下面的示例沿用同一套流程，复制后即可直接执行。

## 使用示例

### 保护任意敏感信息

先加密，再拆分：

```shell
printf '%s' 'my sensitive data' | dpass encrypt | dpass split -o secret -n 5 -m 3
```

不需要加密时，也可以直接拆分明文：

```shell
printf '%s' 'my sensitive data' | dpass split -o secret -n 5 -m 3
```

从任意一组达到阈值的分片中恢复出加密数据，再解密：

```shell
cat secret-5-3-0.txt secret-5-3-1.txt secret-5-3-2.txt | dpass combine | dpass decrypt
```

恢复直接拆分得到的明文（未经加密）：

```shell
cat secret-5-3-0.txt secret-5-3-1.txt secret-5-3-2.txt | dpass combine
```

### 保护钱包助记词

生成助记词、加密后拆成 9 份，恢复阈值为 4：

```shell
dpass mnemonic | dpass encrypt | dpass split -o wallet-cold -n 9 -m 4
```

还原助记词，派生 Bitcoin 地址并渲染成二维码：

```shell
cat wallet-cold-9-4-0.txt wallet-cold-9-4-1.txt wallet-cold-9-4-2.txt wallet-cold-9-4-3.txt | \
  dpass combine | dpass decrypt | dpass bitcoin | dpass qrcode
```

同样的流程，改为派生 Bitcoin 私钥（WIF）并渲染成二维码：

```shell
cat wallet-cold-9-4-0.txt wallet-cold-9-4-1.txt wallet-cold-9-4-2.txt wallet-cold-9-4-3.txt | \
  dpass combine | dpass decrypt | dpass bitcoin --secret | dpass qrcode
```

还原助记词，并派生 Ethereum 地址：

```shell
cat wallet-cold-9-4-0.txt wallet-cold-9-4-1.txt wallet-cold-9-4-2.txt wallet-cold-9-4-3.txt | \
  dpass combine | dpass decrypt | dpass ethereum
```

## Shell 自动补全

`dpass` 能为多种 shell 生成自动补全脚本。下面分别给出"仅在当前会话生效"和"永久安装"两种用法。

### Zsh

```shell
# 一次性安装
dpass completion zsh > "${fpath[1]}/_dpass"
```

### Bash

```shell
# 在当前会话中加载
source <(dpass completion bash)

# Linux 上一次性安装
dpass completion bash > /etc/bash_completion.d/dpass

# 在装有 Homebrew 的 macOS 上一次性安装
dpass completion bash > "$(brew --prefix)/etc/bash_completion.d/dpass"
```

### Fish

```shell
# 在当前会话中加载
dpass completion fish | source

# 一次性安装
dpass completion fish > ~/.config/fish/completions/dpass.fish
```

### PowerShell

```shell
# 在当前会话中加载
dpass completion powershell | Out-String | Invoke-Expression

# 一次性安装
dpass completion powershell > "$HOME/dpass.ps1"
# 然后把下面这一行加入你的 PowerShell 配置文件 ($PROFILE)：
. "$HOME/dpass.ps1"
```
