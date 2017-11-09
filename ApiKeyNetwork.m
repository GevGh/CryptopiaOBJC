//
//  ExchangeApiKeyNetwork.m
//  CurrencyApp
//
//  Created by Gevorg Ghukasyan on 2017-09-08.
//  Copyright © 2017 Gevorg Ghukasyan. All rights reserved.
//

#import "ExchangeApiKeyNetwork.h"
#import "Constants.h"
#import <CommonCrypto/CommonHMAC.h>
#import "Utility.h"

@implementation ExchangeApiKeyNetwork

+ (instancetype)sharedInstance {
    
    static ExchangeApiKeyNetwork *service;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        
        service = [[ExchangeApiKeyNetwork alloc] init];
    });
    return service;
}

- (void)getBalancesWithType:(ExchangeApiKeyType )exchangeType
                     apiKey:(NSString *)apiKey
                  apiSecret:(NSString *)apiSecret
                 completion:(void(^)(NSDictionary *json))completion {
    
    if (exchangeType == ExchangeApiKeyTypeCryptopia) {
        
        long long timestamp = (long long)([[NSDate date] timeIntervalSince1970] * 1000);
        NSString *nonce = [@(timestamp) stringValue];
        
        NSDictionary *jsonDic = @{};

        NSError *error;
        NSData *jsonData = [NSJSONSerialization dataWithJSONObject:jsonDic
                                                           options:NSJSONWritingPrettyPrinted
                                                             error:&error];
        NSString *jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];


        NSString *payload = [self md5:jsonString];
        NSString *payloadBase64 = [self encodeStringTo64:payload];
        
        NSString *url = @"https://www.cryptopia.co.nz/Api/GetBalance";
        url = [self URLEncodedString:url];
        url = [url lowercaseString];
        
        NSString *hashedPostParam = payloadBase64;
        
        NSString *requestSignature = [NSString stringWithFormat:@"%@POST%@%@%@", apiKey, url, nonce, hashedPostParam];
        
        NSString *requestHMACraw = [self sha256:requestSignature withKey:[self decodeStringTo64:apiSecret]];
        
        NSString *requestHMACsignature = [self encodeStringTo64:requestHMACraw];
        
        NSString *headerValue = [NSString stringWithFormat:@"amx %@:%@:%@", apiKey, requestHMACsignature, nonce];

        NSDictionary *headers = @{ @"Authorization" : headerValue,
                                   @"Content-Type": @"application/json; charset=utf-8"
                                   };
        
        NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://www.cryptopia.co.nz/Api/GetBalance"]
                                                               cachePolicy:NSURLRequestUseProtocolCachePolicy
                                                           timeoutInterval:30.0];
        [request setHTTPMethod:@"POST"];
        [request setAllHTTPHeaderFields:headers];
        [request setHTTPBody:jsonData];
        
        NSURLSession *session = [NSURLSession sharedSession];
        NSURLSessionDataTask *dataTask = [session dataTaskWithRequest:request
                                                    completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                                                        
                                                        dispatch_async(dispatch_get_main_queue(), ^{
                                                            
                                                            
                                                            if (error) {
                                                                NSLog(@"%@", error);
                                                            } else {
                                                                
                                                                NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *) response;
                                                                NSLog(@"%@", httpResponse);
                                                                
                                                                
                                                                NSError* err;
                                                                NSDictionary* json = [NSJSONSerialization JSONObjectWithData:data
                                                                                                                     options:kNilOptions
                                                                                                                       error:&err];
                                                                NSLog(@"%@ %@",err, json);
                                                                
                                                                if (!err && json && [json isKindOfClass:[NSArray class]]) {
                                                                    
                                                                    completion(json);
                                                                    return;
                                                                }
                                                            }
                                                            completion(nil);
                                                        });
                                                    }];
        [dataTask resume];
        return;
    }
    completion(nil);
}

- (NSString *)md5:(NSString *)str
{
    const char *cStr = [str UTF8String];
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CC_MD5( cStr, (int)strlen(cStr), result ); // This is the md5 call
    return [NSString stringWithFormat:
            @"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            result[0], result[1], result[2], result[3],
            result[4], result[5], result[6], result[7],
            result[8], result[9], result[10], result[11],
            result[12], result[13], result[14], result[15]
            ];
}

- (NSString *)URLEncodedString:(NSString *)str
{
    
    NSString *encodedString = (NSString *)
    CFBridgingRelease(CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault,
                                                              (CFStringRef)str,
                                                              NULL,
                                                              (CFStringRef)@"!*'();:@&=+$,/?%#[]",
                                                              kCFStringEncodingUTF8));
    
    return encodedString;
}

- (NSString*)encodeStringTo64:(NSString*)fromString
{
    NSData *plainData = [fromString dataUsingEncoding:NSUTF8StringEncoding];
    NSString *base64String = [plainData base64EncodedStringWithOptions:kNilOptions];
    
    return base64String;
}

- (NSString*)decodeStringTo64:(NSString*)fromString
{
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:fromString options:0];
    NSString *decodedString = [[NSString alloc] initWithData:decodedData encoding:NSUTF8StringEncoding];

    return decodedString;
}

- (NSString *)sha256:(NSString*)data withKey:(NSString *)key {
    
    NSData* dataToHash = [data dataUsingEncoding:NSUTF8StringEncoding];
    NSData* keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    
    CCHmac(kCCHmacAlgSHA256, keyData.bytes, keyData.length, dataToHash.bytes, dataToHash.length, digest);
    
    NSString *sha256Str;
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", digest[i]];
    sha256Str = output;
    return sha256Str;
}

- (NSString *)sha512:(NSString *) input withSalt: (NSString *) salt {
    
    
    const char *cKey  = [salt cStringUsingEncoding:NSUTF8StringEncoding];
    const char *data = [input cStringUsingEncoding:NSUTF8StringEncoding];
    unsigned char digest[CC_SHA512_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA512, cKey, strlen(cKey), data, strlen(data), digest);
    
    NSString *hash;
    
    NSMutableString* output = [NSMutableString stringWithCapacity:CC_SHA512_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_SHA512_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", digest[i]];
    hash = output;
    return hash; 
}

@end
