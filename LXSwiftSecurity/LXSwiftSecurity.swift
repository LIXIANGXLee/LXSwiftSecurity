//
//  LXSwiftEscurityUntil.swift
//  LXSwiftSecurityModule
//
//  Created by XL on 2019/10/24.
//  Copyright © 2020 李响. All rights reserved.
//

import UIKit
import CommonCrypto

public struct  LXSwiftSecurity {
    
    /// 加密解密数据统一回调处理定义名字
    public typealias CallBack<T> = ((T?) -> ())
    
    ///加密后的nsdata数据处理成String
    public static func stringFromResult(_ data: NSData?) -> String? {
        guard let data = data else {  return nil  }
        let pointer = data.bytes
        let result = NSMutableString()
        for i in 0..<data.length {
            result.appendFormat("%02x", pointer.load(fromByteOffset: i, as: CUnsignedChar.self))
        }
        return String(result)
    }
    
    ///生成RSA密钥对，公钥和私钥，支持的SIZE有
    /// sizes for RSA keys are: 512, 768, 1024, 2048.
    public static func generateRSAKeyPair(_ keySize: Int,callBack: (SecKey?,SecKey?) -> ()) {
        
        var publicKeyRef: SecKey?
        var privateKeyRef: SecKey?
        
        let parameters = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: keySize] as [CFString : Any]
        let ret = SecKeyGeneratePair(parameters as CFDictionary, &publicKeyRef, &privateKeyRef)
        if ret == errSecSuccess {
            callBack(publicKeyRef,privateKeyRef)
        }else{
            callBack(nil,nil)
        }
    }
}
