gitCrypto
======

> Crypto Service Provider interface in go.

## Table of Contents

- [Usage](#usage)
- [API](#api)
- [Mockgen](#mockgen)
- [GitCZ](#gitcz)
- [Contribute](#contribute)
- [License](#license)

## Mockgen

Install **mockgen** : `go get github.com/golang/mock/mockgen`

How to use?
   
- source： 指定接口文件
- destination: 生成的文件名
- package:生成文件的包名
- imports: 依赖的需要import的包
- aux_files:接口文件不止一个文件时附加文件
- build_flags: 传递给build工具的参数

Eg.`mockgen -destination mock/mock_crypto.go -package crypto -source crypto.go`

Eg.`mockgen -destination mock/mock_engine.go -package crypto -source engine.go`

## GitCZ

**Note**: Please use command `npm install` if you are the first time to use `git cz` in this repo.

## Contribute

PRs are welcome!

Small note: If editing the Readme, please conform to the [standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

This project is currently under Apache 2.0 license. See the LICENSE file for details
