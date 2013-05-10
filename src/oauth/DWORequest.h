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

#import <Foundation/Foundation.h>

@class DWOTokenPair;

//dreamwidth request interface
@interface DWORequest : NSObject {
    @private
    NSMutableDictionary *oauth_params;
    NSMutableDictionary *params;

    NSURL *url;
    NSData *key;
    NSString *baseString;
}

//properties for the request: the URL and the signature string
@property (readonly,nonatomic) NSURL *url;
@property (readonly,nonatomic) NSString* signatureString;

//URL tokend for the consumer
-(id)initWithURL:(NSURL*)url consumerToken:(DWOTokenPair*)consumer method:(NSString*)method;
-(id)initWithURL:(NSURL*)url consumerToken:(DWOTokenPair*)consumer accessToken:(DWOTokenPair*)access
          method:(NSString*)method;
-(id)initWithURL:(NSURL*)url consumerToken:(DWOTokenPair*)consumer accessToken:(DWOTokenPair*)access
          method:(NSString*)method oauthParameters:(NSDictionary*)oauth_dict extraParameters:(NSDictionary*)dict;

//authorization parameter
-(void)setObject:(id)object forOAuthParameter:(NSString*)key;
-(void)setObject:(id)object forParameter:(NSString*)key;

//refresh functions
-(void)refresh;
-(void)sign;
-(BOOL)signed;

//signature parameteres 
-(NSString*)signatureString;
-(NSDictionary*)allParamaters;
-(NSDictionary*)extraParamaters;

//authorization headers
-(NSString*)authorizationHeader;
-(NSString*)queryString;

//add hash functions for the body text
-(void)addBodyHashForString:(NSString*)body;
-(void)addBodyHashForData:(NSData*)body;

@end
