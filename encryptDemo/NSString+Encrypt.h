//
//  NSString+Encrypt.h
//  encryptDemo
//
//  Created by 小飞鸟 on 2017/12/16.
//  Copyright © 2017年 小飞鸟. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (Encrypt)

/*使用Base64加密*/
+(NSString*)encryptWithBase64:(NSString*)text;
/*使用Base64解密*/
+(NSString*)decryptWithBase64:(NSString*)text;
//md5字符串加密
+(NSString *)md5String:(NSString *)sourceString;
//md5字符串加密 加盐处理
+(NSString *)md5SaltString:(NSString *)sourceString;
//md5data加密
+(NSString *)md5Data:(NSData *)sourceData;
/*HMAC ->MD5加密*/
+ (NSString *)HMACMD5:(NSString *)data key:(NSString *)key;
/*HMAC -> SHA1加密*/
+ (NSString *)HMACSHA1:(NSString *)data key:(NSString *)key;
//DES加密
+(NSString *) encryptUseDES2:(NSString *)plainText key:(NSString *)key Iv:(NSString*)IV;
//DES加密
+(NSString *)decryptUseDES:(NSString *)cipherText key:(NSString *)key  Iv:(NSString*)IV;
//AES加密  AES128 （CBC）
+ (NSString*) AES128Encrypt:(NSString *)plainText Key:(NSString*)key Iv:(NSString*)iv;
//AES加密 AES128 （CBC）
+ (NSString*) AES128Decrypt:(NSString *)encryptText Key:(NSString*)key Iv:(NSString*)iv;

/**
 *  加密方法
 *
 *  @param str   需要加密的字符串
 *  @param path  '.der'格式的公钥文件路径
 */
+ (NSString *)encryptString:(NSString *)str publicKeyWithContentsOfFile:(NSString *)path;

/**
 *  解密方法
 *
 *  @param str       需要解密的字符串
 *  @param path      '.p12'格式的私钥文件路径
 *  @param password  私钥文件密码
 */
+ (NSString *)decryptString:(NSString *)str privateKeyWithContentsOfFile:(NSString *)path password:(NSString *)password;

/**
 *  加密方法
 *
 *  @param str    需要加密的字符串
 *  @param pubKey 公钥字符串
 */
+ (NSString *)encryptString:(NSString *)str publicKey:(NSString *)pubKey;

/**
 *  解密方法
 *
 *  @param str     需要解密的字符串
 *  @param privKey 私钥字符串
 */
+ (NSString *)decryptString:(NSString *)str privateKey:(NSString *)privKey;

@end
