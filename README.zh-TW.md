# dpass [![License](https://img.shields.io/badge/license-BSD%202--Clause-green.svg)](https://opensource.org/licenses/BSD-2-Clause) [![Build Status](https://github.com/rbee3u/dpass/actions/workflows/build.yml/badge.svg)](https://github.com/rbee3u/dpass/actions?query=branch%3Amain)

[English](README.md) | [简体中文](README.zh-CN.md) | 繁體中文

`dpass` 是一個命令列工具，用於透過基於門檻的 Shamir 拆分與恢復來保護敏感資料，並可選擇搭配加密使用。它可以先對資料加密，再將其拆分為多個份額；之後再組合足夠數量的份額恢復原始資料，並在需要時解密。

一個常見的使用場景是保護加密貨幣錢包助記詞。針對這一工作流程，`dpass` 提供了面向錢包的輔助能力，可用於產生 BIP-39 助記詞、為多條鏈派生地址或私鑰，並將可匯入結果渲染為終端 QR Code。

## 功能特性

- 使用可選的 AES-256-GCM 加密保護任何標準輸入資料。
- 將明文或密文拆分為基於門檻的 Shamir 份額。
- 透過組合份額恢復受保護資料，並在適用時對結果解密。
- 為錢包工作流程產生 BIP-39 助記詞。
- 從助記詞派生 Bitcoin、Ethereum、Tron、Solana、Dogecoin 和 Sui 的地址或私鑰。
- 將地址、私鑰或其他載荷渲染為終端 QR Code。

## 安裝

```shell
go install github.com/rbee3u/dpass@latest
```

## 命令概覽

- `encrypt` / `decrypt`：使用基於密碼派生的金鑰，透過 AES-256-GCM 對標準輸入進行加密或解密。
- `split` / `combine`：將標準輸入拆分為 PEM 編碼的 Shamir 份額，或從標準輸入讀取份額並恢復原始資料。
- `mnemonic`：產生隨機的 BIP-39 助記詞。
- `bitcoin`、`ethereum`、`tron`、`solana`、`dogecoin`、`sui`：從標準輸入讀取助記詞，並派生對應鏈的地址或私鑰。
- `qrcode`：將標準輸入渲染為終端 QR Code。
- `completion`：產生 shell 自動補全腳本。

使用 `dpass --help` 查看頂層命令列表，使用 `dpass <command> --help` 查看特定命令的參數說明。

大多數命令都從標準輸入讀取資料，並將結果寫到標準輸出，因此可以自然地透過管線組合。

## 工作流程

一個典型的保護與恢復流程如下：

1. 準備你想保護的敏感資訊。
2. 可選擇使用 `dpass encrypt` 對其加密。
3. 使用 `dpass split` 拆分明文或密文。
4. 將產生的份額分別存放在不同位置。
5. 收集足夠數量、滿足門檻要求的份額。
6. 使用 `dpass combine` 恢復資料。
7. 如果恢復出的資料是密文，再使用 `dpass decrypt` 解密。

當 `split` 搭配 `-o <prefix>` 使用時，輸出檔案會寫為 `<prefix>-<parts>-<threshold>-<index>.txt`。

下面的範例遵循這一流程，並且可以直接複製執行。

## 使用範例

### 保護任何敏感資訊

先加密再拆分：

```shell
printf '%s' 'my sensitive data' | dpass encrypt | dpass split -o secret -n 5 -m 3
```

如果不需要加密，也可以直接拆分明文：

```shell
printf '%s' 'my sensitive data' | dpass split -o secret -n 5 -m 3
```

從任何滿足門檻的份額集合中恢復加密資料，並對其解密：

```shell
cat secret-5-3-0.txt secret-5-3-1.txt secret-5-3-2.txt | dpass combine | dpass decrypt
```

恢復未加密直接拆分的明文：

```shell
cat secret-5-3-0.txt secret-5-3-1.txt secret-5-3-2.txt | dpass combine
```

### 保護錢包助記詞

產生助記詞、加密，並將密文拆分為 9 份，其中門檻為 4：

```shell
dpass mnemonic | dpass encrypt | dpass split -o wallet-cold -n 9 -m 4
```

恢復助記詞，派生 Bitcoin 地址，並將其渲染為 QR Code：

```shell
cat wallet-cold-9-4-0.txt wallet-cold-9-4-1.txt wallet-cold-9-4-2.txt wallet-cold-9-4-3.txt | \
  dpass combine | dpass decrypt | dpass bitcoin | dpass qrcode
```

恢復助記詞，派生 Bitcoin 私鑰（WIF），並將其渲染為 QR Code：

```shell
cat wallet-cold-9-4-0.txt wallet-cold-9-4-1.txt wallet-cold-9-4-2.txt wallet-cold-9-4-3.txt | \
  dpass combine | dpass decrypt | dpass bitcoin --secret | dpass qrcode
```

恢復助記詞並派生 Ethereum 地址：

```shell
cat wallet-cold-9-4-0.txt wallet-cold-9-4-1.txt wallet-cold-9-4-2.txt wallet-cold-9-4-3.txt | \
  dpass combine | dpass decrypt | dpass ethereum
```

## Shell 自動補全

`dpass` 可以為多種 shell 產生自動補全腳本。下面分別展示目前工作階段的載入方式與持久安裝方式。

### Zsh

```shell
# 安裝一次
dpass completion zsh > "${fpath[1]}/_dpass"
```

### Bash

```shell
# 在目前工作階段載入
source <(dpass completion bash)

# 在 Linux 上安裝一次
dpass completion bash > /etc/bash_completion.d/dpass

# 在使用 Homebrew 的 macOS 上安裝一次
dpass completion bash > "$(brew --prefix)/etc/bash_completion.d/dpass"
```

### Fish

```shell
# 在目前工作階段載入
dpass completion fish | source

# 安裝一次
dpass completion fish > ~/.config/fish/completions/dpass.fish
```

### PowerShell

```shell
# 在目前工作階段載入
dpass completion powershell | Out-String | Invoke-Expression

# 安裝一次
dpass completion powershell > "$HOME/dpass.ps1"
# 然後把這一行加入你的 PowerShell 設定檔 ($PROFILE)：
. "$HOME/dpass.ps1"
```
