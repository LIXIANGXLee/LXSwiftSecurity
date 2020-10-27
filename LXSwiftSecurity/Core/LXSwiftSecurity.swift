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

//MARK: - 是一个证书处理扩展
extension LXSwiftSecurity {
        
    ///生成RSA密钥对，公钥和私钥，支持的SIZE有
    /// sizes for RSA keys are: 512, 768, 1024, 2048.
    @discardableResult
    public static func generateRSAKeyPair(_ keySize: Int,callBack: ((SecKey?,SecKey?) -> ())? = nil) -> (SecKey?,SecKey?) {
        
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
        /// 用一个.der格式证书创建一个证书对象
        guard let cer = certificate(from: cerFile) else { return nil }
        return LXSwiftPublicKey(cer)?.key
    }
    
    /// 加载私钥
    ///
    /// - Parameter p12File: 从 p12 文件中读取私钥，一般p12都有密码
    public static func privateKey(from p12File: String, psw: String) -> SecKey? {
        ///导入p12证书解析
        guard let items = secPKCS12(from: p12File, psw: psw) else {  return nil }
        return  LXSwiftPrivateKey(items)?.key
    }
    
    
    /// 验证证书的有效性
    public func trustIsValid(_ trust: SecTrust) -> Bool {
        var isValid = false
        if #available(iOS 12, *) {
            isValid = SecTrustEvaluateWithError(trust, nil)
        } else {
            var result = SecTrustResultType.invalid
            let status = SecTrustEvaluate(trust, &result)
            if status == errSecSuccess {
                let unspecified = SecTrustResultType.unspecified
                let proceed = SecTrustResultType.proceed
                isValid = result == unspecified || result == proceed
            }
        }
        return isValid
    }
    
    /// 导入p12证书解析
    private static func secPKCS12(from file: String , psw: String) -> CFArray? {
        guard let fileData = try? Data(contentsOf: URL(fileURLWithPath: file)) as CFData else { return nil }
        
        let options = [kSecImportExportPassphrase as String: psw] as CFDictionary
        var items : CFArray?
        let status = SecPKCS12Import(fileData, options, &items)
        if status != errSecSuccess || CFArrayGetCount(items) <= 0 {  return nil }
        return items
    }
    
    /// 根据文件 创建证书
    private static func certificate(from file: String ) -> SecCertificate? {
        
        guard let fileData = try? Data(contentsOf: URL(fileURLWithPath: file)) as CFData else { return nil }
        let certificate = SecCertificateCreateWithData(nil, fileData)
        return certificate
    }
  
}
