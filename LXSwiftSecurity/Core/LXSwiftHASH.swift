//
//  LXSwiftHASH.swift
//  LXSwiftSecurity
//
//  Created by XL on 2019/10/25.
//  Copyright © 2020 李响. All rights reserved.
//

import UIKit
import CommonCrypto

public struct LXSwiftHASH {
    
    ///填充方式 
    public enum CCDIGESTType {
        case MD5
        case SHA1
        case SHA224
        case SHA256
        case SHA384
        case SHA512
    }
    
    /// 加密成单向散列函数
    ///
    /// - Parameters:
    /// - data: 要加密的数据
    /// - paddingType:  填充模式
    /// - callBack:  签名的返回结果
    @discardableResult
    public static func hash(with data: NSData, paddingType: LXSwiftHASH.CCDIGESTType, callBack: LXSwiftSecurity.CallBack<NSData>? = nil) -> NSData?{
        
        /// 如果没有数据 则不要往下处理 直接返回即可
        if data.count == 0 {
            callBack?(nil)
            return nil
        }
        
        /// 创建指针
        var bufferBytes: UnsafeMutablePointer<UInt8>
        var bufferLength: Int
        
        switch paddingType {
        case .MD5:
            bufferLength = Int(CC_MD5_DIGEST_LENGTH)
            bufferBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferLength)
            bufferBytes.initialize(to: UInt8(bufferLength))
            CC_MD5(data.bytes, CC_LONG(data.count), bufferBytes)
        case .SHA1:
            bufferLength = Int(CC_SHA1_DIGEST_LENGTH)
            bufferBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferLength)
            bufferBytes.initialize(to: UInt8(bufferLength))
            CC_SHA1(data.bytes, CC_LONG(data.count), bufferBytes)
        case .SHA224:
            bufferLength = Int(CC_SHA224_DIGEST_LENGTH)
            bufferBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferLength)
            bufferBytes.initialize(to: UInt8(bufferLength))
            CC_SHA224(data.bytes, CC_LONG(data.count), bufferBytes)
        case .SHA256:
            bufferLength = Int(CC_SHA256_DIGEST_LENGTH)
            bufferBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferLength)
            bufferBytes.initialize(to: UInt8(bufferLength))
            CC_SHA256(data.bytes, CC_LONG(data.count), bufferBytes)
        case .SHA384:
            bufferLength = Int(CC_SHA384_DIGEST_LENGTH)
            bufferBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferLength)
            bufferBytes.initialize(to: UInt8(bufferLength))
            CC_SHA384(data.bytes, CC_LONG(data.count), bufferBytes)
        case .SHA512:
            bufferLength = Int(CC_SHA512_DIGEST_LENGTH)
            bufferBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferLength)
            bufferBytes.initialize(to: UInt8(bufferLength))
            CC_SHA512(data.bytes, CC_LONG(data.count), bufferBytes)
        }
        
        /// 销毁自己创建的内存
        defer {
            bufferBytes.deinitialize(count: bufferLength)
            bufferBytes.deallocate()
        }
        
        let resultData = NSData(bytes: bufferBytes, length: bufferLength)
        callBack?(resultData)
        return resultData
    }
}
