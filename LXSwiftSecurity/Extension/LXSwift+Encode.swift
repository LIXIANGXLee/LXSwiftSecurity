//
//  LXSwift+Encode.swift
//  LXSwiftSecurity
//
//  Created by XL on 2020/10/26.
//  Copyright © 2020 李响. All rights reserved.
//

import UIKit


//MARK: - 对NSData做一个扩展
extension NSData {
    
    /// 对data base64编码成base64 string
    /// 在加密之后的nsdata 想转换成字符串，建议base64编码成字符串，然后解密时在将base64的字符串，解码成nsdata后进行解密
    public var dataToStringOfBase64Encode: String? {
       return self.base64EncodedString(options: Base64EncodingOptions.init(rawValue: 0))
    }
    
    /// NSData类型转换操作 Array of UInt8
    public func arrayOfBytes() -> [UInt8] {
        let count = self.count / MemoryLayout<UInt8>.size
        var bytesArray = [UInt8](repeating: 0, count: count)
        (self as NSData).getBytes(&bytesArray, length:count * MemoryLayout<UInt8>.size)
        return bytesArray
    }
    
}


//MARK: - 对字符串做一个扩展
extension String {
    
    /// 对 base64 string is  base64编码成 data
    /// 解密时在将base64的字符串，解码成nsdata后进行解密
    public var stringToDataOfBase64Decode: NSData? {
        return NSData(base64Encoded: self, options: NSData.Base64DecodingOptions.init(rawValue: 0))
    }

}
