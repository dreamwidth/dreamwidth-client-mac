/*
 * Copyright (c) 2012, Dreamwidth Studios, LLC.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted
 *   provided that the following conditions are met:
 * 
 *  * Redistributions of source code must retain the above copyright notice, this list of
 *      conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright notice, this list of
 *      conditions and the following disclaimer in the documentation and/or other materials
 *      provided with the distribution.
 *  * Neither the name of the orginization nor the names of its contributors may be used to
 *      endorse or promote products derived from this software without specific prior written
 *      permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#import "DWORequest.h"
#import "DWOTokenPair.h"
#import "DWOClient.h"

#import "NSData+Base64.h"
#import <CommonCrypto/CommonHMAC.h>

static NSString * const OAUTH_SIGNATURE_KEY = @"oauth_signature";

@interface DWORequest ()
-(NSMutableDictionary*)allParamaters_;
@end

@implementation DWORequest

@synthesize url;

-(id)initWithURL:(NSURL*)url_ consumerToken:(DWOTokenPair*)consumer_ method:(NSString*)method_ {
    return [self initWithURL:url_
               consumerToken:consumer_
                 accessToken:nil
                      method:method_
             oauthParameters:nil
             extraParameters:nil];
}

-(id)initWithURL:(NSURL*)url_ consumerToken:(DWOTokenPair*)consumer_ accessToken:(DWOTokenPair*)access_
          method:(NSString*)method_ {
    return [self initWithURL:url_
               consumerToken:consumer_
                 accessToken:access_
                      method:method_
             oauthParameters:nil
             extraParameters:nil]; 
}

-(id)initWithURL:(NSURL*)url_
   consumerToken:(DWOTokenPair*)consumer_
     accessToken:(DWOTokenPair*)access_
          method:(NSString*)method_
 oauthParameters:(NSDictionary*)oauth_dict extraParameters:(NSDictionary*)dict {
    
    if ( ( self = [super init] ) ) {
        if ( oauth_dict == nil ) {
            oauth_params = [NSMutableDictionary new];
        } else {
            oauth_params = [oauth_dict mutableCopy];
        }

        if ( dict == nil ) {
            params = [NSMutableDictionary new];
        } else {
            params = [dict mutableCopy];
        }

        [oauth_params setObject:@"1.0" forKey:@"oauth_version"];

        url = [url_ copy];
        NSString *baseURL =
            [NSString stringWithFormat:@"%@://%@%@",
                [[url scheme] lowercaseString],
                [[url host] lowercaseString],
                [url path]];

        baseString = [[NSString alloc] initWithFormat:@"%@&%@",
            [DWOClient encodeString:method_], [DWOClient encodeString:baseURL]];

        NSMutableString *keyStr = [NSMutableString new];

        if ( consumer_ != nil ) {
            [oauth_params setObject:[consumer_ token] forKey:@"oauth_consumer_key"];
            [keyStr appendString:[DWOClient encodeData:[consumer_ secret]]];
        }

        [keyStr appendString:@"&"];

        if ( access_ != nil ) {
            [oauth_params setObject:[access_ token] forKey:@"oauth_token"];
            [keyStr appendString:[DWOClient encodeData:[access_ secret]]];
        }

        key = [keyStr dataUsingEncoding:NSASCIIStringEncoding];
        [keyStr release];

        [self refresh];
    }
    return self;
}

-(void)setObject:(id)object forOAuthParameter:(NSString*)key_ {
    [oauth_params removeObjectForKey:OAUTH_SIGNATURE_KEY];
    [oauth_params setObject:object forKey:key_];
}

-(void)setObject:(id)object forParameter:(NSString*)key_ {
    [oauth_params removeObjectForKey:OAUTH_SIGNATURE_KEY];
    [params setObject:object forKey:key_];
}

-(void)addBodyHashForString:(NSString*)body {
    [self addBodyHashForData:[body dataUsingEncoding:NSUTF8StringEncoding]];
}

-(void)addBodyHashForData:(NSData*)body {
    [oauth_params removeObjectForKey:OAUTH_SIGNATURE_KEY];

    unsigned char cHASH[CC_SHA1_DIGEST_LENGTH];

    CC_SHA1(body.bytes,body.length,cHASH);

    NSData *hash = [NSData dataWithBytesNoCopy:cHASH length:CC_SHA1_DIGEST_LENGTH
                                  freeWhenDone:NO];

    [oauth_params setObject:[hash base64EncodedString] forKey:@"oauth_body_hash"];
}

-(NSMutableDictionary*)allParamaters_ {
    NSMutableDictionary *ov = [params mutableCopy];
    for ( NSString *key_ in [oauth_params allKeys] )
        [ov setObject:[oauth_params objectForKey:key_] forKey:key_];
    return [ov autorelease];
}

-(NSDictionary*)allParamaters {
    if ( ! [self signed] )
        [self sign];
    return [self allParamaters_];
}

-(NSDictionary*)extraParamaters {
    return [[params copy] autorelease];
}

-(NSString*)authorizationHeader {
    if ( ! [self signed] )
        [self sign];

    NSArray *keyArray = [oauth_params allKeys];
    keyArray = [keyArray sortedArrayUsingSelector:@selector(compare:)];
    NSMutableString *outString = [NSMutableString stringWithCapacity:256];

    BOOL commaWanted = NO;
    for ( NSString *key_ in keyArray ) {
        NSString *encoded = [DWOClient encodeObject:[oauth_params objectForKey:key_]];
        if ( encoded == nil ) continue;
        
        [outString appendFormat:( @"%@%@=\"%@\"" ),
            ( commaWanted ? @", " : @"" ),
            [DWOClient encodeString:key_], encoded];
        commaWanted = YES;
    }
    return [NSString stringWithFormat:@"OAauth %@",outString];
}

-(NSString*)queryString {
    if ( ! [self signed] )
        [self sign];

    NSDictionary *dict = [self allParamaters];
    NSArray *keyArray = [dict allKeys];
    keyArray = [keyArray sortedArrayUsingSelector:@selector(compare:)];
    NSMutableString *outString = [NSMutableString stringWithCapacity:256];
    
    BOOL commaWanted = NO;
    for ( NSString *key_ in keyArray ) {
        NSString *encoded = [DWOClient encodeObject:[dict objectForKey:key_]];
        if ( encoded == nil ) continue;
        
        [outString appendFormat:( commaWanted ? @"&%@=%@" : @"%@=%@" ),
         [DWOClient encodeString:key_], encoded];
        commaWanted = YES;
    }
    return outString;
}

-(NSString*)signatureString {
    NSDictionary *dict = [self allParamaters_];
    NSArray *keyArray = [dict allKeys];
    keyArray = [keyArray sortedArrayUsingSelector:@selector(compare:)];

    NSMutableString *rv = [NSMutableString stringWithCapacity:256];
    BOOL wantAmpresand = NO;

    for (NSString *key_ in keyArray) {
        if ( [key_ compare:@"oauth_signature"] == NSOrderedSame )
            continue;

        NSString *encoded = [DWOClient encodeObject:[dict objectForKey:key_]];
        if ( encoded == nil ) continue;

        [rv appendFormat:@"%@%@=%@", ( wantAmpresand ? @"&" : @"" ), [DWOClient encodeString:key_], encoded];
        wantAmpresand = YES;
    }
    return [baseString stringByAppendingFormat:@"&%@", [DWOClient encodeString:rv]];
}

-(void)refresh {
    NSDate *date = [NSDate date];
    long timestamp = (long)[date timeIntervalSince1970];
    
    [oauth_params setObject:[NSNumber numberWithLong:timestamp] forKey:@"oauth_timestamp"];
    [oauth_params setObject:[DWOClient createRandomStringOfLength:16] forKey:@"oauth_nonce"];
    [oauth_params setObject:@"HMAC-SHA1" forKey:@"oauth_signature_method"];

    [oauth_params removeObjectForKey:OAUTH_SIGNATURE_KEY];
}

-(NSString*)signature {
    unsigned char cHMAC[CC_SHA1_DIGEST_LENGTH];

    NSString *sigString = [self signatureString];

    CCHmac(kCCHmacAlgSHA1, key.bytes, key.length, [sigString UTF8String], [sigString length], cHMAC);

    NSData *data = [NSData dataWithBytesNoCopy:cHMAC length:CC_SHA1_DIGEST_LENGTH
                                  freeWhenDone:NO];
    return [data base64EncodedString];
}

-(void)sign {
    [self refresh];
    [oauth_params setObject:[self signature] forKey:OAUTH_SIGNATURE_KEY];
}

-(BOOL)signed {
    return [oauth_params objectForKey:OAUTH_SIGNATURE_KEY] != nil;
}

@end
