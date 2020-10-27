//
//  LXSwiftPrivateKey.swift
//  LXSwiftSecurity
//
//  Created by XL on 2020/10/27.
//  Copyright © 2020 李响. All rights reserved.
//

import UIKit

//MARK: - 私钥获取
public struct LXSwiftPrivateKey {
    
    public var key: SecKey? = nil
    public init?(_  items: CFArray) {
        self.key = privateKey(for: items)
    }
    
    /// 创建私玥 items 检索p12证书后得到的数组
    private func privateKey(for items: CFArray) -> SecKey? {
        let dict = unsafeBitCast(CFArrayGetValueAtIndex(items, 0),to: CFDictionary.self)
        let key = Unmanaged.passUnretained(kSecImportItemIdentity).toOpaque()
        let value = CFDictionaryGetValue(dict, key)
        let secIdentity = unsafeBitCast(value, to: SecIdentity.self)
        
        var privateKey: SecKey?
        let status = SecIdentityCopyPrivateKey(secIdentity, &privateKey)
        if status != errSecSuccess { return nil  }
        
        return privateKey
    }
    
}

