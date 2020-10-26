//
//  ViewController.swift
//  LXSwiftSecurityModule
//
//  Created by XL on 2020/10/24.
//  Copyright © 2020 李响. All rights reserved.
//

import UIKit
import LXSwiftSecurity

class ViewController: UIViewController {
    
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        self.view.backgroundColor = UIColor.red
        
        setAes()
        setRsa()
        setHash()
        setcer()
    }
    
    func setcer() {
        
        guard let srcData = "我是一名iOS开发工程师，解决加密问题".data(using: .utf8) as NSData? else { return }
        LXSwiftSecurity.generateRSAKeyPair(1024) { (pubKey, priKey) in
            LXSwiftHASH.hash(with: srcData, paddingType: .MD5) { (d) in
                let d = LXSwiftSign.sign(with: srcData, privateKey: priKey, paddingType: .SHA256, callBack: nil)
                LXSwiftSign.verifySign(with: srcData, signData: d!, publicKey: pubKey, paddingType: .SHA256) { (isVersign) in
                    print("======\(isVersign!)")
                    
                }
            }
        }
    }
    
    func setAes() {
        
        print("*****开始验证*Aes****")
        
        guard let srcData = "我是一名iOS开发工程师，解决加密问题".data(using: .utf8) as NSData? else { return }
        guard let key16 = "0123456789123456".data(using: .utf8) as NSData? else { return  }
        guard  let iv16 = "0123456789654321".data(using: .utf8) as NSData? else { return  }
        
        LXSwiftAES.AES_CBC_Encrypt(with: srcData, key: key16, iv: iv16) { (data) in
            
             let  base64 =  data!.dataToStringOfBase64Encode
             let baseData = base64?.stringToDataOfBase64Decode!
             print("======\(base64!)==\(baseData!)==\(data!)")

            
            LXSwiftAES.AES_CBC_Decrypt(with: data!, key: key16, iv: iv16) { (data) in
                assert(srcData == data!, "aes_cbc加密失败")
            }
        }
        
        LXSwiftAES.AES_ECB_Encrypt(with: srcData, key: key16) { (data) in
            LXSwiftAES.AES_ECB_Decrypt(with: data!, key: key16) { (data) in
                assert(srcData == data!, "aes_ecb加密失败")
            }
        }
        print("*****结束验证*Aes****")
    }
    
    
    func setRsa() {
        
        print("*****开始验证*Rsa****")
        guard let srcData = "我是一名iOS开发工程师，解决加密问题".data(using: .utf8) as NSData? else { return }
        
//
//       let  (pubKey, priKey) =  LXSwiftSecurity.generateRSAKeyPair(1024)
//       let d = LXSwiftRSA.RSA_Encrypt(with: srcData, publicKey: pubKey, paddingType: .PKCS1)
//       let d1 = LXSwiftRSA.RSA_Decrypt(with: d!, privateKey: priKey, paddingType: .PKCS1)
//
//        if d1! == srcData {
//            print("==RSA_Encrypt===\(d1!)===\(srcData)")
//
//        }
//
//
        LXSwiftSecurity.generateRSAKeyPair(1024) { (pubKey, priKey) in
            LXSwiftRSA.RSA_Encrypt(with: srcData, publicKey: pubKey, paddingType: LXSwiftRSA.RSAPaddingType.PKCS1) { (data) in
                LXSwiftRSA.RSA_Decrypt(with: data!, privateKey: priKey, paddingType: LXSwiftRSA.RSAPaddingType.PKCS1) { (data) in
                    assert(srcData == data!, "rsa加密失败")
                }
            }
        }
        print("*****结束验证*Rsa****")
        
    }
    
    
    func setHash() {
        
        print("*****开始验证*hash****")
        guard let srcData = "我是一名iOS开发工程师，解决加密问题".data(using: .utf8) as NSData? else { return }
        LXSwiftHASH.hash(with: srcData, paddingType: .MD5) { (data) in
            assert(LXSwiftSecurity.stringFromResult(data) == "70961f4ad3f355060bbe2f84bc976662", "MD5加密失败")
        }
        LXSwiftHASH.hash(with: srcData, paddingType: .SHA1) { (data) in
            assert(LXSwiftSecurity.stringFromResult(data) == "2c2cdc570a3c4b62e8da4edc6ac967af3e1e3f97", "SHA1加密失败")
        }
        LXSwiftHASH.hash(with: srcData, paddingType: .SHA256) { (data) in
            assert(LXSwiftSecurity.stringFromResult(data) == "484baa7f4c0f05027bb7c68882ff8397512cce8e909fc08725983bde38e8ce41", "SHA256加密失败")
        }
        LXSwiftHASH.hash(with: srcData, paddingType: .SHA384) { (data) in
            assert(LXSwiftSecurity.stringFromResult(data) == "028c7dc2af4cf9a927f6b3d9acd453b1c046bf1e6dcf26533780cd33252bde8ac7b666aba16959588d82a52d81ede533", "SSHA384加密失败")
        }
        LXSwiftHASH.hash(with: srcData, paddingType: .SHA512) { (data) in
            assert(LXSwiftSecurity.stringFromResult(data) == "8c0eab1b8d22bd4c0a7f112dbe45a7a5b54da24a36c9fab04581abd2ec4264f46783e5fb781d75c1e6cf231dafba8e22bea58ddcf477b2f911ac9a9324025a36", "SHA512加密失败")
        }
        
        print("*****结束验证*hash****")
        
    }
    
}

