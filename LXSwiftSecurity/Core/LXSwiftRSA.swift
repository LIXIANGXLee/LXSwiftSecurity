//
//  LXSwiftRSA.swift
//  LXSwiftSecurity
//
//  Created by XL on 2019/10/25.
//  Copyright © 2020 李响. All rights reserved.
//

import UIKit

public struct LXSwiftRSA {
    
    public enum RSAPaddingType {
        
        ///填充方式pkcs1,最大数据块为 blockSize -11
        case PKCS1
        //填充方式OAEP, 最大数据块为 blockSize -42
        case OAEP
        
        /// 填充方式转换
        var secPadd: SecPadding {
            switch (self) {
            case .PKCS1: return SecPadding.PKCS1
            case .OAEP:  return SecPadding.OAEP
            }
        }
    }
    
    ///RSA 加密
    ///
    /// - Parameters:
    /// - data: 要加密的数据
    /// - publicKey: 加密用的公钥
    /// - paddingType:  填充模式
    /// - callBack:  数据加密后的返回结果
    @discardableResult
    public static func RSA_Encrypt(with data: NSData, publicKey: SecKey?, paddingType: LXSwiftRSA.RSAPaddingType, callBack: LXSwiftSecurity.CallBack<NSData>? = nil) -> NSData? {
        return RSA_Encrypt_Decrypt(isEncrypt: true, data: data, key: publicKey, paddingType: paddingType, callBack: callBack)
    }
    
    ///RSA 解密
    ///
    /// - Parameters:
    /// - data: 要解密的数据
    /// - priKey: 解密用的私钥
    /// - paddingType:  填充模式
    /// - callBack:  数据解密后的返回结果
    @discardableResult
    public static func RSA_Decrypt(with data: NSData, privateKey: SecKey?, paddingType: LXSwiftRSA.RSAPaddingType, callBack: LXSwiftSecurity.CallBack<NSData>? = nil) -> NSData? {
        return RSA_Encrypt_Decrypt(isEncrypt: false, data: data, key: privateKey, paddingType: paddingType, callBack: callBack)
    }
    
    
    ///RSA  加密和解密
    ///
    /// - Parameters:
    /// - data: 要解密的数据或者要加密事的数据
    /// - publicKey: 加密用的公钥或解密用的私钥
    /// - paddingType:  填充模式
    /// - callBack:  数据加密或者解密的返回结果
    @discardableResult
    private static func RSA_Encrypt_Decrypt(isEncrypt: Bool, data: NSData, key: SecKey?, paddingType: LXSwiftRSA.RSAPaddingType, callBack: LXSwiftSecurity.CallBack<NSData>? = nil) -> NSData? {
        
        /// 如果没有数据 或者没有密钥 则不要往下处理 直接返回即可
        guard let key = key, data.count > 0 else {
            callBack?(nil)
            return nil
        }
        
        /// 指针类型转换
        let dataBytes = data.bytes.assumingMemoryBound(to: UInt8.self)
        
        /// 输出数据时需要的可用空间大小。数据缓冲区的大小（字节）
        var bufferLength =  SecKeyGetBlockSize(key)
        let bufferPointer = UnsafeMutableRawPointer.allocate(byteCount: bufferLength, alignment: 1)
        let bufferBytes = bufferPointer.assumingMemoryBound(to: UInt8.self)
        
        /// 填充模式
        let rsaPadd: SecPadding = paddingType.secPadd
       
        /// 销毁自己创建的内存
        defer { bufferBytes.deallocate() }
        
        var cryptStatus: OSStatus
        if isEncrypt { /// 开始加密
            cryptStatus = SecKeyEncrypt(key, rsaPadd, dataBytes, data.length, bufferBytes, &bufferLength)
        }else{///开始解密
            cryptStatus = SecKeyDecrypt(key, rsaPadd, dataBytes, data.length, bufferBytes,  &bufferLength)
        }
        
        /// 加密成功或者解密成功
        if cryptStatus == errSecSuccess {
            let d = NSData(bytes: bufferBytes, length: bufferLength)
            callBack?(d)
            return d
        }else{///加密或者解密失败
            callBack?(nil)
            return nil
        }
    }
}
