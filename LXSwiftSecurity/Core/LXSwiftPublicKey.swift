//
//  LXSwiftPublicKey.swift
//  LXSwiftSecurity
//
//  Created by XL on 2020/10/27.
//  Copyright © 2020 李响. All rights reserved.
//

import UIKit

//MARK: - 公钥获取
public struct LXSwiftPublicKey {
    
    public var key: SecKey? = nil
    public init?(_ certificate: SecCertificate) {
        self.key = publicKey(for: certificate)
    }
    
    /// 创建公钥
    private func publicKey(for certificate: SecCertificate) -> SecKey? {
        var publicKey: SecKey?
        
        /// 返回一个默认 X509 策略的公钥对象
        let policy = SecPolicyCreateBasicX509()
        var trust: SecTrust?
        /// 基于证书和策略创建一个信任管理对象
        let status = SecTrustCreateWithCertificates(certificate, policy, &trust)
        
        if let trust = trust, status == errSecSuccess {
            publicKey = SecTrustCopyPublicKey(trust)
        }
        
        return publicKey
    }
}
