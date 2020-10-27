//
//  ViewController.swift
//  LXSwiftSecurityModule
//
//  Created by XL on 2020/10/24.
//  Copyright © 2020 李响. All rights reserved.
//

import UIKit
//import LXSwiftSecurity

class ViewController: UIViewController {
    
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        self.view.backgroundColor = UIColor.red
        
        
        
        //        guard let cer = Bundle.main.path(forResource: "CPPUB.cer", ofType: nil) else { return  }
        //        guard let p12 = Bundle.main.path(forResource: "CPPRI.p12", ofType: nil) else { return  }
        //
        //        let pubKey = LXSwiftSecurity.publicKey(from: cer)
        //        let priKey = LXSwiftSecurity.privateKey(from: p12, psw: "test")
        //
        
        setAes()
        setRsa()
        setHash()
        setcer()
    }
    
    func setcer() {
        
        guard let srcData = "我是一名iOS开发工程师，解决加密问题".data(using: .utf8) as NSData? else { return }

        LXSwiftSecurity.generateRSAKeyPair(1024) { (pubKey, priKey) in
            guard let hashData = LXSwiftHASH.hash(with: srcData, paddingType: .SHA256) else { return }
            guard let signData = hashData.sign(with: priKey, paddingType:  .SHA256) else { return }
            let isPassVery = hashData.verifySign(with: pubKey, signData: signData, paddingType: .SHA256)
            print("===签名verifySign==\(isPassVery)")
            assert(isPassVery == true, "aes_cbc加密失败")
        }
    }
    
    func setAes() {
        
        guard let srcData = "我是一名iOS开发工程师，解决加密问题".data(using: .utf8) as NSData? else { return }
        guard let key16 = "0123456789123456".data(using: .utf8) as NSData? else { return  }
        guard  let iv16 = "0123456789654321".data(using: .utf8) as NSData? else { return  }
        
        
        guard let enDataCBC = srcData.AES_CBC_Encrypt(with: key16, iv: iv16) else { return }
        guard let deDataCBC = enDataCBC.AES_CBC_Decrypt(with: key16, iv: iv16) else { return }
        print("-=-=-=-AES_CBC==\(String(describing: String(bytes: deDataCBC, encoding: .utf8)))")
        assert(srcData == deDataCBC, "aes_cbc加密失败")
        
        
        guard let enDataECB = srcData.AES_ECB_Encrypt(with: key16) else { return }
        guard let deDataECB = enDataECB.AES_ECB_Decrypt(with: key16) else { return }
        print("-=-=-=-AES_ECB==\(String(describing: String(bytes: deDataECB, encoding: .utf8)))")
        assert(srcData == deDataECB, "aes_ecb加密失败")
    }
    
    
    func setRsa() {
        guard let srcData = "222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222".data(using: .utf8) as NSData? else { return }
        LXSwiftSecurity.generateRSAKeyPair(1024) { (pubKey, priKey) in
            guard let enData = srcData.RSA_Encrypt(with: pubKey, paddingType: .PKCS1) else { return }
            guard let deData = enData.RSA_Decrypt(with: priKey, paddingType: .PKCS1) else { return }
            print("-=-=-=RSA=\(String(describing: String(bytes: deData, encoding: .utf8)))")
            assert(srcData == deData, "rsa加密失败")
        }
    }
    
    
    func setHash() {
        
        print("*****开始验证*hash****")
        guard let srcData = "我是一名iOS开发工程师，解决加密问题".data(using: .utf8) as NSData? else { return }
        
        guard let md5Data = srcData.hash(with: .MD5) else { return }
        assert(md5Data.dataToString == "70961f4ad3f355060bbe2f84bc976662", "MD5加密失败")
        
        guard let shah1Data = srcData.hash(with: .SHA1) else { return }
        assert(shah1Data.dataToString == "2c2cdc570a3c4b62e8da4edc6ac967af3e1e3f97", "SHA1加密失败")
        
        guard let shah256Data = srcData.hash(with: .SHA256) else { return }
        assert(shah256Data.dataToString == "484baa7f4c0f05027bb7c68882ff8397512cce8e909fc08725983bde38e8ce41", "SHA256加密失败")

        guard let shah384Data = srcData.hash(with: .SHA384) else { return }
        assert(shah384Data.dataToString == "028c7dc2af4cf9a927f6b3d9acd453b1c046bf1e6dcf26533780cd33252bde8ac7b666aba16959588d82a52d81ede533", "SSHA384加密失败")

        guard let shah512Data = srcData.hash(with: .SHA512) else { return }
        assert(shah512Data.dataToString == "8c0eab1b8d22bd4c0a7f112dbe45a7a5b54da24a36c9fab04581abd2ec4264f46783e5fb781d75c1e6cf231dafba8e22bea58ddcf477b2f911ac9a9324025a36", "SHA512加密失败")

        print("*****结束验证*hash****")
    }
    
}

