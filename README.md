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

## Q & A

### Q: 为什么你需要加密货币?
A: 在时代的洪流里面个体是非常脆弱的，将来的某一天(但愿永远不会)你可能会面临绝境，不得不背井离乡。房产和贵重金属无法携带，纸币和银行储蓄变得一文不值。为什么你需要加密货币，因为你需要一种可靠的资产转移手段。

### Q: 加密货币能放交易所吗?
A: 能，但这和把黄金存银行没有本质区别。

### Q: 私钥为什么不要直接保存在纸上?
A: 风险1. 容易泄漏；风险2. 容易遗失。

### Q: 私钥为什么不要直接保存在云上?
A: 风险1. 更容易泄漏；风险2. 更容易遗失。

### Q: 保存到1PASS这类密码管理器呢?
A: 风险1. 没有开源；风险2. 密码泄漏。

### Q: 那私钥到底应该如何保存?
A: 加密 & 拆分 & 冗余。

### Q: 如何加密?
A: 先用 argon2 派生再用 aes256 加密。

### Q: 如何拆分?
A: 使用 shamir 算法拆成碎片。

### Q: 如何冗余?
A: 不同碎片分散存储，相同碎片做好备份。

### 

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
