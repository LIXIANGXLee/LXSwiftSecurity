//
//  LXSwiftSignVerify.swift
//  LXSwiftSecurity
//
//  Created by XL on 2019/10/25.
//  Copyright © 2020 李响. All rights reserved.
//

import UIKit

public struct LXSwiftSign {
    
    ///主要使用PKCS1 方式的填充，最大签名数据长度为blockSize-11
    ///签名数据 一般签名，数据的HASH值；
    public enum SECPaddingType {
        case SHA1
        case SHA224
        case SHA256
        case SHA384
        case SHA512
        
        /// 填充方式转换
        var secPadd: SecPadding {
            switch (self) {
            case .SHA1:   return SecPadding.PKCS1SHA1
            case .SHA224: return SecPadding.PKCS1SHA224
            case .SHA256: return SecPadding.PKCS1SHA256
            case .SHA384: return SecPadding.PKCS1SHA384
            case .SHA512: return SecPadding.PKCS1SHA512
            }
        }
    }
        
    /// 签名
    ///
    /// - Parameters:
    /// - data: 要签名的数据
    /// - privateKey: 签名的私钥
    /// - paddingType:  填充模式
    /// - callBack:  签名的返回结果
    @discardableResult
    public static func sign(with data: NSData, privateKey: SecKey?, paddingType: LXSwiftSign.SECPaddingType, callBack: LXSwiftSecurity.CallBack<NSData>? = nil) -> NSData? {
        /// 如果没有数据 或者没有密钥 则不要往下处理 直接返回即可
        guard let key = privateKey, data.count > 0  else {
            callBack?(nil)
            return nil
        }
        
        /// 指针类型转换
        let dataBytes = data.bytes.assumingMemoryBound(to: UInt8.self)
        
        /// 创建缓冲区
        /// 输出数据时需要的可用空间大小。数据缓冲区的大小（字节）
        var bufferLength =  SecKeyGetBlockSize(key)
        let bufferPointer = UnsafeMutableRawPointer.allocate(byteCount: bufferLength, alignment: 1)
        let bufferBytes = bufferPointer.assumingMemoryBound(to: UInt8.self)
        
        /// 填充模式
        let secPadd = paddingType.secPadd
       
        let cryptStatus = SecKeyRawSign(key, secPadd, dataBytes, data.length, bufferBytes, &bufferLength)
        
        defer { bufferBytes.deallocate() }
        
        /// 签名或者签名验证成功
        if cryptStatus == errSecSuccess {
            let d = NSData(bytes: bufferBytes, length: bufferLength)
            callBack?(d)
            return d
        }else{///加密或者解密失败
            callBack?(nil)
            return nil
        }
    }
    
    /// 验证签名
    ///
    /// - Parameters:
    /// - data: 要验证签名的数据
    /// - signData 已签名的数据
    /// - publicKey: 验证签名的公钥
    /// - paddingType:  填充模式
    /// - callBack:  验证签名的返回结果
    @discardableResult
    public static func verifySign(with data: NSData, signData: NSData, publicKey: SecKey?, paddingType: LXSwiftSign.SECPaddingType, callBack: LXSwiftSecurity.CallBack<Bool>? = nil) -> Bool {
        /// 如果没有数据 或者没有密钥 则不要往下处理 直接返回即可
        guard let key = publicKey, data.count > 0  else {
            callBack?(false)
            return false
        }
        
        /// 指针类型转换
        let dataBytes = data.bytes.assumingMemoryBound(to: UInt8.self)
        let signDataBytes = signData.bytes.assumingMemoryBound(to: UInt8.self)
        
        /// 填充模式
        let secPadd = paddingType.secPadd
        
        /// 开始验证签名
        let  cryptStatus = SecKeyRawVerify(key, secPadd, dataBytes, data.count, signDataBytes, signData.count)
        
        /// 签名或者签名验证成功
        if cryptStatus == errSecSuccess {
            callBack?(true)
            return true
        }else{///加密或者解密失败
            callBack?(false)
            return false
        }
    }
}
