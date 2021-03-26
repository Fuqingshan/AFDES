// AFSecurityPolicy.h
// Copyright (c) 2011–2016 Alamofire Software Foundation ( http://alamofire.org/ )
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import <Foundation/Foundation.h>
#import <Security/Security.h>

typedef NS_ENUM(NSUInteger, AFSSLPinningMode) {
    AFSSLPinningModeNone,//不适用固定证书验证服务端，直接从客户端系统受信任的CA列表验证
    AFSSLPinningModePublicKey,//对服务器公钥的publicKey做验证，这种比较适合证书过期之后，新证书不换publicKey 的情况
    AFSSLPinningModeCertificate,//全部都要和本地证书进行校验，包括有效期
};

/**
 `AFSecurityPolicy` evaluates server trust against pinned X.509 certificates and public keys over secure connections.

 Adding pinned SSL certificates to your app helps prevent man-in-the-middle attacks and other vulnerabilities. Applications dealing with sensitive customer data or financial information are strongly encouraged to route all communication over an HTTPS connection with SSL pinning configured and enabled.
 */

NS_ASSUME_NONNULL_BEGIN

/*https连接过程
 1、客户端把支持的ssl/tls（安全套接字协议和安全传输协议）版本等发给服务端
 2、服务端一般保存这公钥和私钥，公钥发给别人，私钥自己保存。服务端验证之后把公钥、数字证书、随机数发给客户端
 3、客户端通过数字证书验证公钥，最顶层是打入系统的CA认证根证书。
 3.5、这儿根据安全性要求，进行单向认证或双向认证，可能客户端要把证书和自己的公钥发给服务器，服务器做验证（双向）
 4、客户端把支持的对称加密算法发给服务端，服务端选择之后，如果之前有客户端的公钥，则用公钥加密发给客户端，如果没有，则明文发送
 5、客户端用自己的私钥解密之后，把加密秘钥用服务端的公钥加密，发给服务端
 5、服务端解密，对称秘钥进行数据加密通讯
 
 总结：数据通讯时用的是对称加密，加密速度快，非对称加密的是对称加密所需要的秘钥
 
 把https简化成两个人通信：
 A有公钥和私钥，B也有公钥和私钥，AB的公钥是公开的。
 A要给B发消息，就用B的公钥加密，发给B，B用私钥解密
 B要给A发消息，就用A的公钥加密，发给A，A用私钥解密
 
 为了加快后续通讯的加解密速度，首次通讯时，A加密的信息就变成了对称加密的秘钥，然后发给B，B拿着这个秘钥之后，后续通讯就用这个秘钥来加解密了。
 
 这儿A就相当于服务端，B就是客户端。
 
 而数字证书就是为了防止中间人劫持，对数据进行篡改，用来做验证的。
 
 数字签名：A的公钥->hash成消息摘要->CA私钥加密->数字签名
 数字证书：A的公钥+数字签名
 B拿到数字证书之后：
 1、A的公钥->hash成消息摘要
 2、通过CA的公钥解密数字签名->消息摘要
 3、对比两个摘要，验证公钥是否合法，公钥合法，那么对应的对称加密秘钥也就合法了

 */

@interface AFSecurityPolicy : NSObject <NSSecureCoding, NSCopying>

/**
 The criteria by which server trust should be evaluated against the pinned SSL certificates. Defaults to `AFSSLPinningModeNone`.
 */
@property (readonly, nonatomic, assign) AFSSLPinningMode SSLPinningMode;

/**
 The certificates used to evaluate server trust according to the SSL pinning mode. 
 
 Note that if pinning is enabled, `evaluateServerTrust:forDomain:` will return true if any pinned certificate matches.

 @see policyWithPinningMode:withPinnedCertificates:
 */
@property (nonatomic, strong, nullable) NSSet <NSData *> *pinnedCertificates;

/**
 Whether or not to trust servers with an invalid or expired SSL certificates. Defaults to `NO`.
 */
@property (nonatomic, assign) BOOL allowInvalidCertificates;

/**
 Whether or not to validate the domain name in the certificate's CN field. Defaults to `YES`.
 */
@property (nonatomic, assign) BOOL validatesDomainName;

///-----------------------------------------
/// @name Getting Certificates from the Bundle
///-----------------------------------------

/**
 Returns any certificates included in the bundle. If you are using AFNetworking as an embedded framework, you must use this method to find the certificates you have included in your app bundle, and use them when creating your security policy by calling `policyWithPinningMode:withPinnedCertificates`.

 @return The certificates included in the given bundle.
 */
+ (NSSet <NSData *> *)certificatesInBundle:(NSBundle *)bundle;

///-----------------------------------------
/// @name Getting Specific Security Policies
///-----------------------------------------

/**
 Returns the shared default security policy, which does not allow invalid certificates, validates domain name, and does not validate against pinned certificates or public keys.

 @return The default security policy.
 */
+ (instancetype)defaultPolicy;

///---------------------
/// @name Initialization
///---------------------

/**
 Creates and returns a security policy with the specified pinning mode.
 
 Certificates with the `.cer` extension found in the main bundle will be pinned. If you want more control over which certificates are pinned, please use `policyWithPinningMode:withPinnedCertificates:` instead.

 @param pinningMode The SSL pinning mode.

 @return A new security policy.

 @see -policyWithPinningMode:withPinnedCertificates:
 */
+ (instancetype)policyWithPinningMode:(AFSSLPinningMode)pinningMode;

/**
 Creates and returns a security policy with the specified pinning mode.

 @param pinningMode The SSL pinning mode.
 @param pinnedCertificates The certificates to pin against.

 @return A new security policy.

 @see +certificatesInBundle:
 @see -pinnedCertificates
*/
+ (instancetype)policyWithPinningMode:(AFSSLPinningMode)pinningMode withPinnedCertificates:(NSSet <NSData *> *)pinnedCertificates;

///------------------------------
/// @name Evaluating Server Trust
///------------------------------

/**
 Whether or not the specified server trust should be accepted, based on the security policy.

 This method should be used when responding to an authentication challenge from a server.

 @param serverTrust The X.509 certificate trust of the server.
 @param domain The domain of serverTrust. If `nil`, the domain will not be validated.

 @return Whether or not to trust the server.
 */
- (BOOL)evaluateServerTrust:(SecTrustRef)serverTrust
                  forDomain:(nullable NSString *)domain;

@end

NS_ASSUME_NONNULL_END

///----------------
/// @name Constants
///----------------

/**
 ## SSL Pinning Modes

 The following constants are provided by `AFSSLPinningMode` as possible SSL pinning modes.

 enum {
 AFSSLPinningModeNone,
 AFSSLPinningModePublicKey,
 AFSSLPinningModeCertificate,
 }

 `AFSSLPinningModeNone`
 Do not used pinned certificates to validate servers.

 `AFSSLPinningModePublicKey`
 Validate host certificates against public keys of pinned certificates.

 `AFSSLPinningModeCertificate`
 Validate host certificates against pinned certificates.
*/
