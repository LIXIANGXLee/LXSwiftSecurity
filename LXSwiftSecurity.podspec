#
#  Be sure to run `pod spec lint LXSwiftSecurity.podspec' to ensure this is a
#  valid spec and to remove all comments including this before submitting the spec.
#
#  To learn more about Podspec attributes see https://guides.cocoapods.org/syntax/podspec.html
#  To see working Podspecs in the CocoaPods repo see https://github.com/CocoaPods/Specs/
#

Pod::Spec.new do |spec|
    
    # ―――  Spec Metadata  ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――― #
    #
    #  These will help people to find your library, and whilst it
    #  can feel like a chore to fill in it's definitely to your advantage. The
    #  summary should be tweet-length, and the description more in depth.
    #
    
    spec.name         = "LXSwiftSecurity"
    spec.version      = "4.0.0"
    spec.summary      = "swift加密方式md5/SHA1/SHA224/SHA256/SHA384/SHA512/AES/RSA/签名/验证签名"
    
    
    spec.description  = <<-DESC
    LXSwiftSecurity is manager swift加密方式md5/SHA1/SHA224/SHA256/SHA384/SHA512/AES/RSA/签名/验证签名
    DESC
    
    
    spec.homepage = "https://github.com/LIXIANGXLee/LXSwiftSecurity"
    
    spec.license = "MIT"
    spec.author = { "lixiang" => "1367015013@qq.com" }
    
    spec.platform = :ios, "9.0"
    spec.swift_version = "5.0"
    
    spec.source = { :git => "https://github.com/LIXIANGXLee/LXSwiftSecurity.git", :tag => "#{spec.version}" }
 
    spec.subspec 'Core' do |core|
        core.source_files  = 'LXSwiftSecurity/Core/*.swift'
    end
    
    spec.subspec 'Extension' do |extension|
        extension.source_files  = 'LXSwiftSecurity/Extension/*.swift'
        extension.dependency 'LXSwiftSecurity/Core'
    end
    
    
end

