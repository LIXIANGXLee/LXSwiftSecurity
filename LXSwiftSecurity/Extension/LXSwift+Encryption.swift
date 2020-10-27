//
//  LXSwift+Encryption.swift
//  LXSwiftSecurity
//
//  Created by XL on 2020/10/26.
//  Copyright © 2020 李响. All rights reserved.
//
/// 添加扩展 好用的 便利的加密 解密 签名 验证签名等等

import UIKit

//MARK: - RSA 加密 解密
extension NSData {
    
    ///RSA 加密
    ///
    /// - Parameters:
    /// - publicKey: 加密用的公钥
    /// - paddingType:  填充模式
    public func RSA_Encrypt(with publicKey: SecKey?, paddingType: LXSwiftRSA.RSAPaddingType = .PKCS1) -> NSData?{
        return LXSwiftRSA.RSA_Encrypt(with: self, publicKey: publicKey, paddingType: paddingType)
    }
    
    
    ///RSA 解密
    ///
    /// - Parameters:
    /// - priKey: 解密用的私钥
    /// - paddingType:  填充模式
    public func RSA_Decrypt(with privateKey: SecKey?, paddingType: LXSwiftRSA.RSAPaddingType = .PKCS1) -> NSData?{
        return LXSwiftRSA.RSA_Decrypt(with: self, privateKey: privateKey, paddingType: paddingType)
    }
}

//MARK: - AES 加密 解密
extension NSData {
    
    ///AES 加密 CBC模式加密
    ///
    /// - Parameters:
    /// - key: 长度16字节，24字节，32字节 密钥
    /// - iv:  16字节
    public func AES_CBC_Encrypt(with key: NSData, iv: NSData) -> NSData? {
        return LXSwiftAES.AES_CBC_Encrypt(with: self, key: key, iv: iv)
    }
    
    ///AES 解密 CBC模式加密
    ///
    /// - Parameters:
    /// - key: 长度16字节，24字节，32字节 密钥
    /// - iv:  16字节
    public func AES_CBC_Decrypt(with key: NSData, iv: NSData) -> NSData? {
        return LXSwiftAES.AES_CBC_Decrypt(with: self, key: key, iv: iv)
    }
    
    ///AES 加密 ECB模式加密
    ///
    /// - Parameters:
    /// - key: 长度16字节，24字节，32字节 密钥
    public func AES_ECB_Encrypt(with key: NSData) -> NSData? {
        return LXSwiftAES.AES_ECB_Encrypt(with: self, key: key)
    }
    
    ///AES 解密 ECB模式加密
    ///
    /// - Parameters:
    /// - key: 长度16字节，24字节，32字节 密钥
    public func AES_ECB_Decrypt(with key: NSData) -> NSData? {
        return LXSwiftAES.AES_ECB_Decrypt(with: self, key: key)
    }

}

//MARK: - sign 签名 签名验证
extension NSData {
    
    /// 签名
    ///
    /// - Parameters:
    /// - privateKey: 签名的私钥
    /// - paddingType:  填充模式
    public  func sign(with privateKey: SecKey?, paddingType: LXSwiftSign.SECPaddingType) -> NSData? {
        return LXSwiftSign.sign(with: self, privateKey: privateKey, paddingType: paddingType)
    }
    
    /// 验证签名
    ///
    /// - Parameters:
    /// - signData 已签名的数据
    /// - publicKey: 验证签名的公钥
    /// - paddingType:  填充模式
    public func verifySign(with publicKey: SecKey?, signData: NSData, paddingType: LXSwiftSign.SECPaddingType) -> Bool {
        return LXSwiftSign.verifySign(with: self, signData: signData, publicKey: publicKey, paddingType: paddingType)
    }
    
}

//MARK: - hash 单向散列函数
extension NSData {
    
    /// 加密成单向散列函数
    ///
    /// - Parameters:
    /// - paddingType:  填充模式
    public  func hash(with paddingType: LXSwiftHASH.CCDIGESTType) -> NSData? {
        return LXSwiftHASH.hash(with: self, paddingType: paddingType)
    }
    
    ///加密后的nsdata数据处理成String
    public var dataToString: String? {
        let result = NSMutableString()
        for i in 0..<self.length {
            result.appendFormat("%02x", self.bytes.load(fromByteOffset: i, as: CUnsignedChar.self))
        }
        return String(result)
    }
    
}
