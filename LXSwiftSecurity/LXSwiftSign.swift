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
    }
    
    /// 签名
    ///
    /// - Parameters:
    /// - data: 要签名的数据
    /// - privateKey: 签名的私钥
    /// - paddingType:  填充模式
    /// - callBack:  签名的返回结果
    public static func sign(with data: NSData, privateKey: SecKey?, paddingType: LXSwiftSign.SECPaddingType, callBack: LXSwiftSecurity.CallBack<NSData>) {
        sign_verifySign(isSign: true, data: data, key: privateKey, paddingType: paddingType, callBack: callBack)
    }
    
    /// 签名
    ///
    /// - Parameters:
    /// - data: 要验证签名的数据
    /// - publicKey: 验证签名的公钥
    /// - paddingType:  填充模式
    /// - callBack:  验证签名的返回结果
    public static func verifySign(with data: NSData, publicKey: SecKey?, paddingType: LXSwiftSign.SECPaddingType, callBack: LXSwiftSecurity.CallBack<NSData>) {
        sign_verifySign(isSign: false, data: data, key: publicKey, paddingType: paddingType, callBack: callBack)
    }
    
    /// 签名  或者 验证签名
    ///
    /// - Parameters:
    /// - data: 签名数据或者要验证签名的数据
    /// - privateKey: 签名的私钥或者验证签名的公钥
    /// - paddingType:  填充模式
    /// - callBack:    签名或者验证签名的返回结果
    
    private static func sign_verifySign(isSign: Bool, data: NSData, key: SecKey?, paddingType: LXSwiftSign.SECPaddingType, callBack: LXSwiftSecurity.CallBack<NSData>) {
        
        if data.count == 0 || key == nil { return }
        /// 指针类型转换
        let dataBytes = data.bytes.assumingMemoryBound(to: UInt8.self)
        
        /// 输出数据时需要的可用空间大小。数据缓冲区的大小（字节）
        var bufferLength =  SecKeyGetBlockSize(key!)
        let bufferBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferLength)
        bufferBytes.initialize(to: UInt8(bufferLength))
        
        /// 填充模式
        var secPadd: SecPadding
        switch (paddingType) {
        case .SHA1:
            secPadd = SecPadding.PKCS1SHA1
        case .SHA224:
            secPadd = SecPadding.PKCS1SHA224
        case .SHA256:
            secPadd = SecPadding.PKCS1SHA256
        case .SHA384:
            secPadd = SecPadding.PKCS1SHA384
        case .SHA512:
            secPadd = SecPadding.PKCS1SHA512
        }
        
        /// 销毁自己创建的内存
        defer {
            bufferBytes.deinitialize(count: bufferLength)
            bufferBytes.deallocate()
        }
        
        var cryptStatus: OSStatus
        if isSign { /// 开始签名
            cryptStatus = SecKeyRawSign(key!, secPadd, dataBytes, data.length, bufferBytes, &bufferLength)
        }else{/// 开始验证签名
            cryptStatus = SecKeyRawVerify(key!, secPadd, dataBytes, data.length, bufferBytes, bufferLength)
        }
        
        /// 加密成功或者解密成功
        if cryptStatus == errSecSuccess {
            callBack(NSData(bytes: bufferBytes, length: bufferLength))
        }else{///加密或者解密失败
            callBack(nil)
        }
    }
}
