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
    
}

extension LXSwiftSecurity {
    
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
    @discardableResult
    public static func generateRSAKeyPair(_ keySize: Int,callBack: ((SecKey?,SecKey?) -> ())?) -> (SecKey?,SecKey?) {
        
        var publicKeyRef: SecKey?
        var privateKeyRef: SecKey?
        
        let parameters = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: keySize] as [CFString : Any]
        let ret = SecKeyGeneratePair(parameters as CFDictionary, &publicKeyRef, &privateKeyRef)
        if ret == errSecSuccess {
            callBack?(publicKeyRef,privateKeyRef)
            return (publicKeyRef,privateKeyRef)
        }else{
            callBack?(nil,nil)
            return (nil,nil)
        }
    }
        
    /// 加载公钥
    ///
    /// - Parameter filePath: 从x509 cer证书中读取公钥
    public static func publicKey(from cerFile: String) -> SecKey? {
       
        guard let certData =  NSData(contentsOfFile: cerFile) else { return nil }
        /// 用一个.der格式证书创建一个证书对象
        let cert = SecCertificateCreateWithData(kCFAllocatorDefault, certData)
        
        /// 返回一个默认 X509 策略的公钥对象
        let  policy = SecPolicyCreateBasicX509()
        
        /// 包含信任管理信息的结构体
        var  trustRef: SecTrust?
        
        /// 基于证书和策略创建一个信任管理对象
        var status = SecTrustCreateWithCertificates(cert as CFTypeRef, policy, &trustRef)
        if status != errSecSuccess { return nil }
        
        /// 信任结果
        var trustResult = SecTrustResultType.invalid
        /// 评估指定证书和策略的信任管理是否有效
        status = SecTrustEvaluate(trustRef!, &trustResult)
        if status != errSecSuccess {  return nil  }
        
        // 评估之后返回公钥子证书
        let  publicKeyRef = SecTrustCopyPublicKey(trustRef!)
        if publicKeyRef == nil { return nil }
        
        return publicKeyRef
    }    
    
    /// 加载私钥
    ///
    /// - Parameter p12File: 从 p12 文件中读取私钥，一般p12都有密码
    public static func privateKey(from p12File: String, psw: String) -> SecKey? {
      
        guard let p12Data =  NSData(contentsOfFile: p12File) else { return nil }
        
        let options = [kSecImportExportPassphrase as String: psw]
        var items : CFArray?
        let status = SecPKCS12Import(p12Data as CFData, options as CFDictionary, &items)
        if status != errSecSuccess {  return nil }
        if CFArrayGetCount(items) <= 0 { return nil }
        
        
        let dict = unsafeBitCast(CFArrayGetValueAtIndex(items, 0),to: CFDictionary.self)
        let key = Unmanaged.passUnretained(kSecImportItemIdentity).toOpaque()
        let value = CFDictionaryGetValue(dict, key)
        let secIdentity = unsafeBitCast(value, to: SecIdentity.self)
        
        var privateKeyRef: SecKey?
        let secIdentityCopyPrivateKey = SecIdentityCopyPrivateKey(secIdentity, &privateKeyRef)
        if secIdentityCopyPrivateKey != errSecSuccess { return nil  }
        return privateKeyRef
    }
    
}
