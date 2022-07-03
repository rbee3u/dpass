# dpass [![License](https://img.shields.io/badge/license-BSD%202--Clause-green.svg)](https://opensource.org/licenses/BSD-2-Clause) [![Build Status](https://github.com/rbee3u/dpass/actions/workflows/build.yml/badge.svg)](https://github.com/rbee3u/dpass/actions?query=branch%3Amain)

## dpass

### 安装
```shell
go install github.com/rbee3u/dpass/cmd/dpass@latest
```

### 配置自动补全
```shell
# zsh 示例
dpass completion zsh > "${fpath[1]}/_dpass"
```

## dcoin

### 安装
```shell
go install github.com/rbee3u/dpass/cmd/dcoin@latest
```

### 配置自动补全
```shell
# zsh 示例
dcoin completion zsh > "${fpath[1]}/_dcoin"
```

## 推荐使用场景
```shell
# 1. 生成一个冷钱包助记词
# 2. 将这个助记词进行加密
# 3. 将密文分解成9个碎片(任意4个碎片可以合成)
# 4. 将这9个碎片分散存储
dcoin mnemonic | dpass encrypt | dpass split -o wallet-cold -n 9 -m 4
```

```shell
# 1. 集齐任意4个密文碎片
# 2. 将碎片合成得到密文
# 3. 解密得到助记词明文
# 4. 使用助记词计算BTC地址
# 5. 将BTC地址转换成二维码(用于导入观察钱包)
cat wallet-cold-9-4-* | dpass combine | dpass decrypt | dcoin bitcoin | dpass qrcode
```

```shell
# 1. 集齐任意4个密文碎片
# 2. 将碎片合成得到密文
# 3. 解密得到助记词明文
# 4. 使用助记词计算BTC私钥
# 5. 将BTC私钥转换成二维码(用于导入冷钱包)
cat wallet-cold-9-4-* | dpass combine | dpass decrypt | dcoin bitcoin --secret | dpass qrcode
```

当然 dpass 和 dcoin 能做的事情远不止上面，更多的使用场景欢迎高端玩家尽情探索。
