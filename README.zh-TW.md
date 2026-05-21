# dpass [![License](https://img.shields.io/badge/license-BSD%202--Clause-green.svg)](https://opensource.org/licenses/BSD-2-Clause) [![Build Status](https://github.com/rbee3u/dpass/actions/workflows/build.yml/badge.svg)](https://github.com/rbee3u/dpass/actions/workflows/build.yml?query=branch%3Amain)

[English](README.md) | [简体中文](README.zh-CN.md) | 繁體中文

`dpass` 是一款命令列工具，運用門檻式的 Shamir 拆分與還原機制來保護敏感資料，並可選配一層加密。流程很直接：必要時先加密，再把結果拆成多份分片；日後再湊齊足夠數量的分片即可還原原始資料，需要的話再解密回來。

它最常見的用途，是保管加密貨幣錢包的助記詞。針對這個情境，`dpass` 內建了一組錢包小工具，可用來產生 BIP-39 助記詞、為多條鏈派生地址或私鑰，並把可匯入的結果直接渲染成終端機 QR Code。

## 為什麼會有 dpass

對部分人而言，加密貨幣最看重的從來不是炒作，而是它的可攜性與自我託管。一旦碰上危機、被迫遷徙，或當地體制不再可靠時，能跨境帶走的數位資產，也許就是少數仍握在自己手中的財產形式。可一旦資產能隨身帶走，新的麻煩也跟著浮現：助記詞或私鑰究竟該怎麼保管，才能既不把控制權交回別人手上，也不至於把安全全押在單一節點上？

`dpass` 給出的答案很樸素：

- 乾脆放在交易所行不行？那等於把託管權重新交回給機構。既然目的是自己作主，交易所就不該是最終歸宿。
- 那直接抄在紙上呢？孤伶伶的一份實體副本，被竊、受損或遺失只是遲早的事。
- 放到雲端或密碼管理器又如何？這類服務一樣可能洩密、把你鎖在門外，或者悄悄變成新的單點。
- 那這個專案到底主張怎麼做？先把助記詞或私鑰加密，再拆成需達到門檻才能還原的多份分片，分散保存，並保留必要的冗餘。

這正是 `dpass` 想要支援的工作流程。

## 功能特性

- 可選配 AES-256-GCM，對來自標準輸入的任意資料進行加密保護。
- 把明文或密文按門檻拆分成 Shamir 分片。
- 湊齊分片即可還原受保護的資料，必要時一併解密。
- 為錢包情境產生 BIP-39 助記詞。
- 從助記詞派生 Bitcoin、Ethereum、Tron、Solana、Dogecoin、Sui 的地址或私鑰。
- 把地址、私鑰或其他酬載渲染成終端機 QR Code。

## 安裝

### Homebrew（macOS / Linux）

透過專案 tap 安裝：

```shell
brew tap rbee3u/dpass
brew install dpass
```

日後升級到新版本：

```shell
brew upgrade dpass
```

### 預先編譯的二進位

每次發版都會把 Linux 與 macOS 上 amd64、arm64 架構的預先編譯二進位放上 [Releases 頁面](https://github.com/rbee3u/dpass/releases)。挑一份對應你系統的壓縮檔，解壓後把 `dpass` 放到 `PATH` 下就能用。

```shell
tar -xzf dpass_<version>_<os>_<arch>.tar.gz
sudo mv dpass /usr/local/bin/
dpass --version
```

每個版本還會附上一份 `dpass_<version>_checksums.txt`，可以用 `sha256sum -c` 確認下載檔案是否完整。

### 從原始碼安裝

```shell
go install github.com/rbee3u/dpass@v1.6.2
```

## 命令概覽

- `encrypt` / `decrypt`：以密碼派生出的金鑰，對標準輸入進行 AES-256-GCM 加解密。
- `split` / `combine`：把標準輸入拆成 PEM 編碼的 Shamir 分片，或反過來從標準輸入讀取分片、還原出原始資料。
- `mnemonic`：產生一組隨機的 BIP-39 助記詞。
- `bitcoin`、`ethereum`、`tron`、`solana`、`dogecoin`、`sui`：從標準輸入讀取助記詞，並派生對應鏈的地址或私鑰。
- `qrcode`：把標準輸入渲染為終端機 QR Code。
- `completion`：產生 shell 自動補全腳本。

`dpass --help` 會列出所有頂層命令，`dpass <command> --help` 則顯示個別命令的參數說明。

多數命令都從標準輸入讀取、向標準輸出寫出，因此可以很自然地用管線串接起來。

## 工作流程

典型的保護與還原流程是這樣的：

1. 準備好你想保護的敏感資訊。
2. 如有需要，用 `dpass encrypt` 替它加上一層加密。
3. 用 `dpass split` 把明文或密文拆成多個分片。
4. 把每份分片分別存放在不同地點。
5. 日後湊齊數量達到門檻的分片。
6. 用 `dpass combine` 還原資料。
7. 若還原出來的是密文，再用 `dpass decrypt` 解密。

`split` 搭配 `-o <prefix>` 使用時，輸出檔案會寫成 `<prefix>-<parts>-<threshold>-<index>.txt`。

下方範例皆沿用此流程，複製後即可直接執行。

## 使用範例

### 保護任何敏感資訊

先加密，再拆分：

```shell
printf '%s' 'my sensitive data' | dpass encrypt | dpass split -o secret -n 5 -m 3
```

若不需要加密，也可以直接拆分明文：

```shell
printf '%s' 'my sensitive data' | dpass split -o secret -n 5 -m 3
```

從任意一組達到門檻的分片中還原出加密資料，再解密：

```shell
cat secret-5-3-0.txt secret-5-3-1.txt secret-5-3-2.txt | dpass combine | dpass decrypt
```

還原直接拆分得到的明文（未經加密）：

```shell
cat secret-5-3-0.txt secret-5-3-1.txt secret-5-3-2.txt | dpass combine
```

### 保護錢包助記詞

產生助記詞、加密後拆成 9 份，門檻設為 4：

```shell
dpass mnemonic | dpass encrypt | dpass split -o wallet-cold -n 9 -m 4
```

還原助記詞，派生 Bitcoin 地址並渲染成 QR Code：

```shell
cat wallet-cold-9-4-0.txt wallet-cold-9-4-1.txt wallet-cold-9-4-2.txt wallet-cold-9-4-3.txt | \
  dpass combine | dpass decrypt | dpass bitcoin | dpass qrcode
```

同樣的流程，改為派生 Bitcoin 私鑰（WIF）並渲染成 QR Code：

```shell
cat wallet-cold-9-4-0.txt wallet-cold-9-4-1.txt wallet-cold-9-4-2.txt wallet-cold-9-4-3.txt | \
  dpass combine | dpass decrypt | dpass bitcoin --secret | dpass qrcode
```

還原助記詞，並派生 Ethereum 地址：

```shell
cat wallet-cold-9-4-0.txt wallet-cold-9-4-1.txt wallet-cold-9-4-2.txt wallet-cold-9-4-3.txt | \
  dpass combine | dpass decrypt | dpass ethereum
```

## Shell 自動補全

若你以 Homebrew 安裝 `dpass`，補全腳本已自動安裝好——Homebrew 會把它放進自己管理的補全目錄，並隨 `brew upgrade` 一起更新，本節可直接略過。

其他安裝方式（`go install`、預先編譯的壓縮檔等）需要自行產生腳本，並放到對應 shell 搜尋補全的目錄下。下方每種 shell 都給出「僅在目前工作階段載入」與「永久安裝」兩種寫法。

### Zsh

```shell
# 僅在目前工作階段載入
source <(dpass completion zsh)

# 永久安裝：把上面這行追加到 ~/.zshrc 末尾即可
```

Oh My Zsh、Prezto 這類框架會自動初始化補全系統，所以追加到 `~/.zshrc` 就夠用了。若你用的是沒有初始化補全的純淨 zsh，只需在那行 `source` 之前補一次 `autoload -Uz compinit && compinit`。

請勿再使用 `dpass completion zsh > "${fpath[1]}/_dpass"` 這種寫法：`fpath[1]` 會隨當下 shell 與外掛載入順序而變，常常落到毫不相關的外掛目錄（例如 Oh My Zsh 某個內建外掛），把補全檔案寫到奇怪的位置，並把後續套件管理工具（如 Homebrew）安裝的新版本蓋在底下。

### Bash

```shell
# 僅在目前工作階段載入
source <(dpass completion bash)

# Linux 上永久安裝
dpass completion bash > /etc/bash_completion.d/dpass
```

在 macOS 上，bash 補全本身就建立在 Homebrew 的 `bash-completion` 套件之上，而 `brew install dpass` 已經把腳本放進該套件要求的目錄，因此這裡不再單獨列手動指令。

### Fish

```shell
# 僅在目前工作階段載入
dpass completion fish | source

# 永久安裝
dpass completion fish > ~/.config/fish/completions/dpass.fish
```
