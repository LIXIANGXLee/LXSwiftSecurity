//
//  LXSwift+AES.swift
//  LXSwiftSecurity
//
//  Created by 李响 on 2019/10/24.
//

import UIKit
import CommonCrypto

/**
 支持的AES key size 加密有 128位，192位，256位
 数据填充方式：kCCOptionPKCS7Padding
 分组模式：CBC 和 EBC
 */
public struct LXSwiftAES {
    
    ///AES 加密 CBC模式加密
    ///
    /// - Parameters:
    /// - data: 要加密的数据
    /// - key: 长度16字节，24字节，32字节 密钥
    /// - iv:  16字节
    /// - callBack:  数据加密后的返回结果
    @discardableResult
    public static func AES_CBC_Encrypt(with data: NSData, key: NSData, iv: NSData, callBack: LXSwiftSecurity.CallBack<NSData>? = nil) -> NSData? {
        return AES_Encrypt_Decrypt(isEncrypt: true, data: data, key: key, iv: iv, callBack: callBack)
    }
    
    ///AES 解密 CBC模式加密
    ///
    /// - Parameters:
    /// - data: 要解密的数据
    /// - key: 长度16字节，24字节，32字节 密钥
    /// - iv:  16字节
    /// - callBack:  数据解密后的返回结果
    @discardableResult
    public static func AES_CBC_Decrypt(with data: NSData, key: NSData, iv: NSData, callBack: LXSwiftSecurity.CallBack<NSData>? = nil) -> NSData? {
        return AES_Encrypt_Decrypt(isEncrypt: false, data: data, key: key, iv: iv, callBack: callBack)
    }
    
    ///AES 加密 ECB模式加密
    ///
    /// - Parameters:
    /// - data: 要加密的数据
    /// - key: 长度16字节，24字节，32字节 密钥
    /// - callBack:  数据加密后的返回结果
    @discardableResult
    public static func AES_ECB_Encrypt(with data: NSData, key: NSData, callBack: LXSwiftSecurity.CallBack<NSData>? = nil) -> NSData? {
        AES_Encrypt_Decrypt(isEncrypt: true, data: data, key: key, iv: nil, callBack: callBack)
    }
    
    ///AES 解密 ECB模式加密
    ///
    /// - Parameters:
    /// - data: 要解密的数据
    /// - key: 长度16字节，24字节，32字节 密钥
    /// - callBack:  数据解密后的返回结果
    @discardableResult
    public static func AES_ECB_Decrypt(with data: NSData, key: NSData, callBack: LXSwiftSecurity.CallBack<NSData>? = nil) -> NSData? {
        AES_Encrypt_Decrypt(isEncrypt: false, data: data, key: key, iv: nil, callBack: callBack)
    }
    
    ///AES 加密或者解密 CBC或者CBC模式加密和解密
    ///
    /// - Parameters:
    /// - isEncrypt 区分是加密和解密
    /// - data: 要解密的数据 或者要加密的数据
    /// - key: 长度16字节，24字节，32字节 密钥
    /// - iv:  16字节。如果是ECB模式 则传nil即可
    /// - callBack:  数据解密后的返回结果
    @discardableResult
    private static func AES_Encrypt_Decrypt(isEncrypt: Bool , data: NSData, key: NSData, iv: NSData?, callBack: LXSwiftSecurity.CallBack<NSData>? = nil) -> NSData?  {
        
        /// 如果没有数据 或者没有密钥 则不要往下处理 直接返回即可
        if data.count == 0 || key.count == 0 {
            callBack?(nil)
            return nil
        }
        
        /// 加密或者解密
        let kCCType = isEncrypt ? CCOperation(kCCEncrypt) : CCOperation(kCCDecrypt)
        /// 加密的计算方式
        let algorithm = CCAlgorithm(kCCAlgorithmAES128)
        
        /// 选择的补码方式，以及是否选择CBC模式，默认是ECB模式
        var options = CCOptions(kCCOptionPKCS7Padding|kCCOptionECBMode)
        
        var ivBytes: UnsafeRawPointer? = nil
        if let iv = iv {
            ///偏移向量，CBC模式下需要；不传默认16位0，只有在ECB模式下不需要
            ivBytes = iv.bytes
            ///加密填充方式 CBC
            options = CCOptions(kCCOptionPKCS7Padding)
        }
        
        /// 输出数据时需要的可用空间大小。数据缓冲区的大小（字节）
        let bufferSize =  data.count + kCCBlockSizeAES128
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: bufferSize, alignment: 1)
        
        ///操作成功之后，被写入dataout的字节长度。如果由于提供的缓冲区空间不足而返回kCCBufferTooSmall，则在这里返回所需的缓冲区空间
        let numBytesEncrypt = UnsafeMutablePointer<Int>.allocate(capacity: 1)
        numBytesEncrypt.initialize(to: 1)
        
        /// 开始加密或者可是解密
        let cryptStatus = CCCrypt(kCCType, algorithm, options, key.bytes, key.length,ivBytes, data.bytes, data.length, buffer, bufferSize, numBytesEncrypt)
        
        /// 销毁自己创建的内存
        defer {
            numBytesEncrypt.deinitialize(count: 1)
            numBytesEncrypt.deallocate()
            buffer.deallocate()
        }
        
        /// 加密成功或者解密成功
        if cryptStatus == kCCSuccess {
            let d = NSData(bytes: buffer, length: numBytesEncrypt.pointee)
            callBack?(d)
            return d
        }else{///加密或者解密失败
            callBack?(nil)
            return nil
        }
    }
}

