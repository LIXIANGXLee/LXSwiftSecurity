# LXSwiftSecurity

#### 项目介绍

###  技术探讨可加本人qq：3141833116@qq.com

 **

###    swift加密方式md5/SHA1/SHA224/SHA256/SHA384/SHA512/AES/RSA/签名/验证签名

** 

#### 安装说明
方式1 ： cocoapods安装库 
        ** pod 'LXSwiftSecurity' **
        ** pod install ** 

方式2:   **直接下载压缩包 解压**    **LXSwiftSecurity **   

#### 使用说明
 **下载后压缩包 解压   请先 pod install  在运行项目** 
  
**支持多种函数调用方式、灵活调用、灵活使用 完美**

#### 签名 和验证签名
```
guard let hashData = LXSwiftHASH.hash(with: srcData, paddingType: .SHA256) else { return }
guard let signData = hashData.sign(with: priKey, paddingType:  .SHA256) else { return }
let isPassVery = hashData.verifySign(with: pubKey, signData: signData, paddingType: .SHA256)

```

#### RSA加密和解密 
```
guard let enData = srcData.RSA_Encrypt(with: pubKey, paddingType: .PKCS1) else { return }
guard let deData = enData.RSA_Decrypt(with: priKey, paddingType: .PKCS1) else { return }

```
#### AES_CBC 加密和解密
```
guard let enDataCBC = srcData.AES_CBC_Encrypt(with: key16, iv: iv16) else { return }
guard let deDataCBC = enDataCBC.AES_CBC_Decrypt(with: key16, iv: iv16) else { return }

```
#### AES_ECB 加密和解密
```
guard let enDataECB = srcData.AES_ECB_Encrypt(with: key16) else { return }
guard let deDataECB = enDataECB.AES_ECB_Decrypt(with: key16) else { return }

```
#### SHAH单向散列函数 1、224、256、384、512、 MD5 示例仅展示两个
```
guard let srcData = "我是一名iOS开发工程师，解决加密问题".data(using: .utf8) as NSData? else { return }

guard let md5Data = srcData.hash(with: .MD5) else { return }
assert(md5Data.dataToString == "70961f4ad3f355060bbe2f84bc976662", "MD5加密失败")

guard let shah256Data = srcData.hash(with: .SHA256) else { return }
assert(shah256Data.dataToString == "2c2cdc570a3c4b62e8da4edc6ac967af3e1e3f97", "SHA1加密失败")

```

#### 根据证书创建公钥和私玥
```
let pubKey = LXSwiftSecurity.publicKey(from: cer)
let priKey = LXSwiftSecurity.privateKey(from: p12, psw: "test")

```

