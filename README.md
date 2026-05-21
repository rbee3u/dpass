# dpass [![License](https://img.shields.io/badge/license-BSD%202--Clause-green.svg)](https://opensource.org/licenses/BSD-2-Clause) [![Build Status](https://github.com/rbee3u/dpass/actions/workflows/build.yml/badge.svg)](https://github.com/rbee3u/dpass/actions?query=branch%3Amain)

English | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md)

`dpass` is a command-line tool that protects secrets by splitting them into threshold-based Shamir shares, with an optional encryption pass beforehand. Encrypt first if you want that extra layer, then split the result; later, combine enough shares to recover the original data and decrypt it if needed.

A common use case is protecting cryptocurrency wallet mnemonics. For that workflow, `dpass` ships helpers that generate BIP-39 mnemonics, derive addresses or private keys across multiple chains, and render importable results straight to a terminal QR code.

## Why This Exists

For some people, cryptocurrency isn't really about speculation. It's about
portability and self-custody. When a crisis hits, a relocation is forced
upon you, or local institutions stop being reliable, digitally portable
assets can be among the few things that still travel with you across
borders. But that portability solves one problem and creates another: how
do you protect the secret that controls the asset without turning it into
a single point of failure?

`dpass` is built around a simple answer:

- Why not just leave assets on an exchange? Because that hands custody back
  to an institution. If the goal is sovereign control, an exchange isn't a
  real long-term answer.
- Why not write the seed or private key on paper? A single physical copy
  can be stolen, damaged, or lost.
- Why not stash it in the cloud or a password manager? Those services can
  still leak the secret, lock you out, or quietly become another single
  point of compromise.
- What does this project recommend instead? Encrypt the mnemonic or
  private key first, split the result into threshold shares, and store
  those shares separately with deliberate redundancy.

That is the workflow `dpass` is designed to support.

## Features

- Optionally encrypt anything from stdin with AES-256-GCM.
- Split plaintext or ciphertext into threshold-based Shamir shares.
- Recover the protected data by combining shares, and decrypt the result when needed.
- Generate BIP-39 mnemonics for wallet workflows.
- Derive addresses or private keys for Bitcoin, Ethereum, Tron, Solana, Dogecoin, and Sui.
- Render addresses, private keys, or other payloads as terminal QR codes.

## Installation

### Homebrew (macOS / Linux)

Install via the project tap:

```shell
brew tap rbee3u/dpass
brew install dpass
```

Upgrade to the latest release later with:

```shell
brew upgrade dpass
```

### Pre-built binaries

Linux and macOS binaries (amd64 and arm64) are published on the
[Releases page](https://github.com/rbee3u/dpass/releases). Download the
archive for your OS and architecture, extract it, and drop `dpass`
somewhere on your `PATH`.

```shell
tar -xzf dpass_<version>_<os>_<arch>.tar.gz
sudo mv dpass /usr/local/bin/
dpass --version
```

Every release also ships `dpass_<version>_checksums.txt`, so you can verify
downloads with `sha256sum -c`.

### Install from source

```shell
go install github.com/rbee3u/dpass@v1.6.0
```

## Command Overview

- `encrypt` / `decrypt`: Run stdin through AES-256-GCM with a password-derived key.
- `split` / `combine`: Split stdin into PEM-encoded Shamir shares, or fold shares from stdin back into the original data.
- `mnemonic`: Generate a random BIP-39 mnemonic.
- `bitcoin`, `ethereum`, `tron`, `solana`, `dogecoin`, `sui`: Read a mnemonic from stdin and derive that chain's address or private key.
- `qrcode`: Render stdin as a terminal QR code.
- `completion`: Generate shell completion scripts.

Run `dpass --help` for the top-level command list, or `dpass <command> --help` for the flags of a single command.

Most commands read from stdin and write to stdout, so they pipe together naturally.

## Workflow

A typical protect-and-recover flow looks like this:

1. Prepare the secret you want to protect.
2. Optionally encrypt it with `dpass encrypt` for an extra layer.
3. Split the plaintext or ciphertext with `dpass split`.
4. Store each share in a different place.
5. Later, gather enough shares to meet the threshold.
6. Recover the data with `dpass combine`.
7. If what you got back is ciphertext, decrypt it with `dpass decrypt`.

With `split -o <prefix>`, output files are written as `<prefix>-<parts>-<threshold>-<index>.txt`.

The examples below follow this same flow and are meant to be copy-pasted as-is.

## Examples

### Protect Any Secret

Encrypt first, then split:

```shell
printf '%s' 'my sensitive data' | dpass encrypt | dpass split -o secret -n 5 -m 3
```

Skip encryption and split the plaintext directly:

```shell
printf '%s' 'my sensitive data' | dpass split -o secret -n 5 -m 3
```

Recover the encrypted data from any share set that meets the threshold, then decrypt it:

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

Same flow, but derive the Bitcoin private key (WIF) instead and render that as a QR code:

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

`dpass` can generate completion scripts for several shells. The snippets below show how to load completions for the current session or install them permanently.

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
