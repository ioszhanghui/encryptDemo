//
//  ViewController.m
//  encryptDemo
//
//  Created by 小飞鸟 on 2017/12/16.
//  Copyright © 2017年 小飞鸟. All rights reserved.
//

#import "ViewController.h"
#import "NSString+Encrypt.h"

@interface ViewController ()

@end

@implementation ViewController

 static  NSString *salt = @"234567890-!@#$%^&*()_+QWERTYUIOP{ASDFGHJKL:XCVBNM<>";

- (void)viewDidLoad {
    [super viewDidLoad];
    
    NSString * pwd =[NSString encryptWithBase64:@"1234567890000"];
    NSLog(@"加密数据%@",pwd);
    NSString * text =[NSString decryptWithBase64:pwd];
    NSLog(@"解密数据***%@",text);
    NSString * md5= [NSString md5String:@"123"];
    NSLog(@"md5****%@",md5);
    
    NSString * saltMD5 =[NSString md5SaltString:[@"123" stringByAppendingString:salt]];
    NSLog(@"SaltMD5****%@",saltMD5);
    
    NSString * HMACMD5 =[NSString HMACMD5:@"123" key:@"123"];
    NSLog(@"HMACMD5****%@",HMACMD5);

    NSString * decryDes=[NSString encryptUseDES2:@"abc123xyz123456" key:salt Iv:@"e9abf371e1e8dd9c"];
    NSLog(@"des加密后的数据%@",decryDes);
    
    NSString * des=[NSString decryptUseDES:decryDes key:salt Iv:@"e9abf371e1e8dd9c"];
    NSLog(@"des解密后的数据%@",des);
 
    
    NSString * AES =[NSString AES128Encrypt:@"abc123xyz123" Key:@"202cb962ac59075b" Iv:@"e9abf371e1e8dd9c"];
    NSString * deAES=[NSString AES128Decrypt:AES Key:@"202cb962ac59075b" Iv:@"e9abf371e1e8dd9c"];
    NSLog(@"AES解密后的数据%@",deAES);
    
    //原始数据
    NSString *originalString = @"这是一段将要使用'.der'文件加密的字符串!";
    
    //使用.der和.p12中的公钥私钥加密解密
    NSString *public_key_path = [[NSBundle mainBundle] pathForResource:@"public_key.der" ofType:nil];
    NSString *private_key_path = [[NSBundle mainBundle] pathForResource:@"private_key.p12" ofType:nil];
    
    NSString *encryptStr = [NSString encryptString:originalString publicKeyWithContentsOfFile:public_key_path];
    NSLog(@"加密前:%@", originalString);
    NSLog(@"加密后:%@", encryptStr);
    NSLog(@"解密后:%@", [NSString decryptString:encryptStr privateKeyWithContentsOfFile:private_key_path password:@"123456"]);
    
}

@end
