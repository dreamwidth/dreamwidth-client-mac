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

#import "DWClient.h"
#import "DWClient+Internal.h"

#import "DWOClient.h"
#import "DWORequest.h"

#import "NSURL+QueryString.h"
#import "NSString+QueryString.h"

#import "AFHTTPRequestOperation.h"
#import "DWPendingAuthorization.h"
#import "DWOTokenPair.h"

static NSString * const REQUEST_ENDPOINT = @"/oauth/request_token";
static NSString * const ACCESS_ENDPOINT = @"/oauth/access_token";
static NSString * const AUTHORIZE_ENDPOINT = @"/oauth/authorize";

static NSDictionary *pendingAuthorizations = nil;

@interface DWClient ()

@end

@implementation DWClient

@synthesize baseEndpoint;
@synthesize sslEnabled;
@synthesize appProtocol;

//basic initailization.
+(void)initialize {
    pendingAuthorizations = [[NSDictionary alloc] init];
}

//enable endpoint  for tokens
- (id)initWithEndpoint:(NSString*)endpoint ssl:(BOOL)ssl tokenPair:(DWOTokenPair*)tokenPair_ {
    if ( (self = [super init]) ) {
        baseEndpoint = [endpoint copy];
        sslEnabled = ssl;
        tokenPair = [tokenPair_ retain];
        appProtocol = nil;
    }
    return self;
}

//for mac client, get the connection URL
- (NSURL *)getAppURLWithPath:(NSString*)path {
    return [[[NSURL alloc] initWithScheme:(sslEnabled ? @"https" : @"http")
                                     host:baseEndpoint
                                     path:path] autorelease];
}

//Now that you have the URL, authorize callback for client
- (void)authorizeUser:(DWAccessTokenCallback)callback begin:(DWBeginAccessTokenCallback)beginCallback {
    if ( appProtocol == nil )
        return callback(YES,nil);

    NSURL *url = [self getAppURLWithPath:REQUEST_ENDPOINT];
    NSString *callbackPath = [NSString stringWithFormat:@"%@://oauth_callback",appProtocol];
    DWORequest *oReq = [DWOClient requestTokenRequestFromURL:url consumer:tokenPair callback:callbackPath];
    
    //URL connection details
    url = [oReq.url URLByAppendingQueryString:oReq.queryString];
    NSURLRequest *uReq = [NSURLRequest requestWithURL:url cachePolicy:NSURLCacheStorageNotAllowed timeoutInterval:30];
    
    AFHTTPRequestOperation *operation = [[AFHTTPRequestOperation alloc] initWithRequest:uReq];
    
    DWPendingAuthorization *pending = [[DWPendingAuthorization alloc]
                                       initWithClient:self operation:operation
                                       accessCallback:callback
                                       beginCallback:beginCallback outOfBand:NO];
    [pending start];
    [pending release];
    [operation release];
}

//Now that connection has been established, establish authorization for the URL.
- (void)authorizeUser:(DWAccessTokenCallback)callback outOfBand:(DWBeginAccessTokenCallback)oobCallback {
    NSURL *url = [self getAppURLWithPath:REQUEST_ENDPOINT];
    DWORequest *oReq = [DWOClient requestTokenRequestFromURL:url consumer:tokenPair callback:@"oob"];
    [oReq setObject:@"true" forParameter:@"simple_verifier"];

    url = [oReq.url URLByAppendingQueryString:oReq.queryString];
    NSURLRequest *uReq = [NSURLRequest requestWithURL:url cachePolicy:NSURLCacheStorageNotAllowed timeoutInterval:30];
    
    AFHTTPRequestOperation *operation = [[AFHTTPRequestOperation alloc] initWithRequest:uReq];

    
    DWPendingAuthorization *pending = [[DWPendingAuthorization alloc]
                                       initWithClient:self operation:operation
                                       accessCallback:callback
                                       beginCallback:oobCallback outOfBand:YES];
    [pending start];
    [pending release];
    [operation release];
}

//handle URL open operations
-(BOOL)maybeHandleOpenURL:(NSURL *)url {
    if ( url == nil || appProtocol == nil ) return NO;
    if ( [url.scheme compare:appProtocol] != NSOrderedSame ) return NO;

    NSString *path = url.path;
    if ( [path compare:@"oauth_callback"] ) {
        NSString *qStr = url.query;
        if ( qStr == nil ) return NO;
        NSDictionary *query = [qStr dictionaryFromQueryString];

        NSData *token;
        NSString *verifier;
        NSString *arg = [query objectForKey:@"oauth_token"];
        if ( arg == nil ) return NO;
        token = [arg dataUsingEncoding:NSUTF8StringEncoding];

        verifier = [query objectForKey:@"oauth_verifier"];
        if ( verifier == nil ) return NO;
        [DWPendingAuthorization gotVerifier:verifier forToken:token];
        return YES;
    }

    return NO;
}

//deallocation  for breakpoints, and release of connection in memory
- (void)dealloc {
    [baseEndpoint release];
    baseEndpoint = nil;

    [tokenPair release];
    tokenPair = nil;

    [appProtocol release];
    appProtocol = nil;

    [super dealloc];
}

@end

@implementation DWClient (Internal)

//authorization of URL with connection with token
- (NSURL *)authorizeURLForToken:(DWOTokenPair*)pair {
    NSURL *rv = [self getAppURLWithPath:AUTHORIZE_ENDPOINT];
    NSString *args = [NSString stringWithFormat:@"oauth_token=%@",
                      [DWOClient encodeData:pair.token]];
    return [rv URLByAppendingQueryString:args];
}

//Access toeken operations, allow authorization.
- (AFHTTPRequestOperation*)accessTokenOperationWithRequest:(DWOTokenPair*)pair andVerifier:(NSString*)verifier {
    NSURL *url = [self getAppURLWithPath:ACCESS_ENDPOINT];
    DWORequest *oReq = [DWOClient accessTokenRequestFromURL:url consumer:tokenPair requestToken:pair verifier:verifier];
    
    url = [oReq.url URLByAppendingQueryString:oReq.queryString];
    NSURLRequest *uReq = [NSURLRequest requestWithURL:url cachePolicy:NSURLCacheStorageNotAllowed timeoutInterval:30];
    
    AFHTTPRequestOperation *operation = [[AFHTTPRequestOperation alloc] initWithRequest:uReq];
    return [operation autorelease];
}

@end
