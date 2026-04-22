# dpass [![License](https://img.shields.io/badge/license-BSD%202--Clause-green.svg)](https://opensource.org/licenses/BSD-2-Clause) [![Build Status](https://github.com/rbee3u/dpass/actions/workflows/build.yml/badge.svg)](https://github.com/rbee3u/dpass/actions?query=branch%3Amain)

English | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md)

`dpass` is a command-line tool for protecting secrets with threshold-based Shamir splitting and recovery, with optional encryption. It can encrypt data before splitting it into shares, then combine enough shares to recover the original data and decrypt it when needed.

One common use case is protecting cryptocurrency wallet mnemonics. For that workflow, `dpass` provides helpers to generate BIP-39 mnemonics, derive addresses or private keys for multiple chains, and render importable results as terminal QR codes.

## Features

- Protect any data from stdin with optional AES-256-GCM encryption.
- Split plaintext or ciphertext into threshold-based Shamir shares.
- Recover protected data by combining shares and, if applicable, decrypting the result.
- Generate BIP-39 mnemonics for wallet workflows.
- Derive addresses or private keys for Bitcoin, Ethereum, Tron, Solana, Dogecoin, and Sui.
- Render addresses, private keys, or other payloads as terminal QR codes.

## Installation

```shell
go install github.com/rbee3u/dpass@latest
```

## Command Overview

- `encrypt` / `decrypt`: Encrypt or decrypt stdin with AES-256-GCM using a password-derived key.
- `split` / `combine`: Split stdin into PEM-encoded Shamir shares, or combine shares from stdin to recover the original data.
- `mnemonic`: Generate a random BIP-39 mnemonic.
- `bitcoin`, `ethereum`, `tron`, `solana`, `dogecoin`, `sui`: Derive chain-specific addresses or private keys from a mnemonic read from stdin.
- `qrcode`: Render stdin as a terminal QR code.
- `completion`: Generate shell completion scripts.

Use `dpass --help` for the top-level command list and `dpass <command> --help` for command-specific flags.

Most commands read from stdin and write to stdout, so they compose naturally in shell pipelines.

## Workflow

A typical protection and recovery flow looks like this:

1. Prepare the secret you want to protect.
2. Optionally encrypt it with `dpass encrypt`.
3. Split the plaintext or ciphertext with `dpass split`.
4. Store the resulting shares separately.
5. Collect enough shares to satisfy the threshold.
6. Recover the data with `dpass combine`.
7. If the recovered data is ciphertext, decrypt it with `dpass decrypt`.

When `split` is used with `-o <prefix>`, output files are written as `<prefix>-<parts>-<threshold>-<index>.txt`.

The examples below follow this same flow and can be copied directly.

## Examples

### Protect Any Secret

Protect a secret with encryption before splitting:

```shell
printf '%s' 'my sensitive data' | dpass encrypt | dpass split -o secret -n 5 -m 3
```

Split plaintext directly when encryption is not required:

```shell
printf '%s' 'my sensitive data' | dpass split -o secret -n 5 -m 3
```

Recover encrypted data from any threshold-satisfying share set and decrypt it:

```shell
cat secret-5-3-0.txt secret-5-3-1.txt secret-5-3-2.txt | dpass combine | dpass decrypt
```

Recover plaintext that was split without encryption:

```shell
cat secret-5-3-0.txt secret-5-3-1.txt secret-5-3-2.txt | dpass combine
```

### Protect a Wallet Mnemonic

Generate a mnemonic, encrypt it, and split the ciphertext into nine shares with a threshold of four:

```shell
dpass mnemonic | dpass encrypt | dpass split -o wallet-cold -n 9 -m 4
```

Recover the mnemonic, derive a Bitcoin address, and render it as a QR code:

```shell
cat wallet-cold-9-4-0.txt wallet-cold-9-4-1.txt wallet-cold-9-4-2.txt wallet-cold-9-4-3.txt | \
  dpass combine | dpass decrypt | dpass bitcoin | dpass qrcode
```

Recover the mnemonic, derive a Bitcoin private key (WIF), and render it as a QR code:

```shell
cat wallet-cold-9-4-0.txt wallet-cold-9-4-1.txt wallet-cold-9-4-2.txt wallet-cold-9-4-3.txt | \
  dpass combine | dpass decrypt | dpass bitcoin --secret | dpass qrcode
```

Recover the mnemonic and derive an Ethereum address:

```shell
cat wallet-cold-9-4-0.txt wallet-cold-9-4-1.txt wallet-cold-9-4-2.txt wallet-cold-9-4-3.txt | \
  dpass combine | dpass decrypt | dpass ethereum
```

## Shell Completion

`dpass` can generate completion scripts for multiple shells. The examples below show how to load completions for the current session or install them persistently.

### Zsh

```shell
# install once
dpass completion zsh > "${fpath[1]}/_dpass"
```

### Bash

```shell
# load for the current session
source <(dpass completion bash)

# install once on Linux
dpass completion bash > /etc/bash_completion.d/dpass

# install once on macOS with Homebrew
dpass completion bash > "$(brew --prefix)/etc/bash_completion.d/dpass"
```

### Fish

```shell
# load for the current session
dpass completion fish | source

# install once
dpass completion fish > ~/.config/fish/completions/dpass.fish
```

### PowerShell

```shell
# load for the current session
dpass completion powershell | Out-String | Invoke-Expression

# install once
dpass completion powershell > "$HOME/dpass.ps1"
# then add this line to your PowerShell profile ($PROFILE):
. "$HOME/dpass.ps1"
```
