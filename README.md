# LXSwiftSecurity

#### 项目介绍
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
  

```

LXSwiftAES.AES_CBC_Encrypt(with: srcData, key: key16, iv: iv16) { (data) in
LXSwiftAES.AES_CBC_Decrypt(with: data!, key: key16, iv: iv16) { (data) in
assert(srcData == data!, "aes_cbc加密失败")
}
}

LXSwiftAES.AES_ECB_Encrypt(with: srcData, key: key16) { (data) in
LXSwiftAES.AES_ECB_Decrypt(with: data!, key: key16) { (data) in
assert(srcData == data!, "aes_ecb加密失败")
}
}



LXSwiftSecurity.generateRSAKeyPair(1024) { (pubKey, priKey) in
LXSwiftRSA.RSA_Encrypt(with: srcData, publicKey: pubKey, paddingType: LXSwiftRSA.RSAPaddingType.PKCS1) { (data) in
LXSwiftRSA.RSA_Decrypt(with: data!, privateKey: priKey, paddingType: LXSwiftRSA.RSAPaddingType.PKCS1) { (data) in
assert(srcData == data!, "rsa加密失败")
}
}
}
guard let srcData = "我是一名iOS开发工程师，解决加密问题".data(using: .utf8) as NSData? else { return }
LXSwiftHASH.hash(with: srcData, paddingType: .MD5) { (str) in
assert(str! == "70961f4ad3f355060bbe2f84bc976662", "MD5加密失败")
}
LXSwiftHASH.hash(with: srcData, paddingType: .SHA1) { (str) in
assert(str! == "2c2cdc570a3c4b62e8da4edc6ac967af3e1e3f97", "SHA1加密失败")
}
LXSwiftHASH.hash(with: srcData, paddingType: .SHA256) { (str) in
assert(str! == "484baa7f4c0f05027bb7c68882ff8397512cce8e909fc08725983bde38e8ce41", "SHA256加密失败")
}
LXSwiftHASH.hash(with: srcData, paddingType: .SHA384) { (str) in
assert(str! == "028c7dc2af4cf9a927f6b3d9acd453b1c046bf1e6dcf26533780cd33252bde8ac7b666aba16959588d82a52d81ede533", "SSHA384加密失败")
}
LXSwiftHASH.hash(with: srcData, paddingType: .SHA512) { (str) in
assert(str! == "8c0eab1b8d22bd4c0a7f112dbe45a7a5b54da24a36c9fab04581abd2ec4264f46783e5fb781d75c1e6cf231dafba8e22bea58ddcf477b2f911ac9a9324025a36", "SHA512加密失败")
}

```

