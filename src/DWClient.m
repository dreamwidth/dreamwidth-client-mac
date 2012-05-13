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


+(void)initialize {
    pendingAuthorizations = [[NSDictionary alloc] init];
}

- (id)initWithEndpoint:(NSString*)endpoint ssl:(BOOL)ssl tokenPair:(DWOTokenPair*)tokenPair_ {
    if ( (self = [super init]) ) {
        baseEndpoint = [endpoint copy];
        sslEnabled = ssl;
        tokenPair = [tokenPair_ retain];
    }
    return self;
}

- (NSURL *)getAppURLWithPath:(NSString*)path {
    return [[[NSURL alloc] initWithScheme:(sslEnabled ? @"https" : @"http")
                                     host:baseEndpoint
                                     path:path] autorelease];
}

- (NSURL *)authorizeURLForToken:(DWOTokenPair*)pair {
    NSURL *rv = [self getAppURLWithPath:AUTHORIZE_ENDPOINT];
    NSString *args = [NSString stringWithFormat:@"oauth_token=%@",
                      [DWOClient encodeData:pair.token]];
    return [rv URLByAppendingQueryString:args];
}

- (void)authorizeUser:(DWAccessTokenCallback)callback {
    callback(true,nil);
}

- (void)authorizeUser:(DWAccessTokenCallback)callback outOfBand:(DWBeginOOBCallback)oobCallback {
    NSURL *url = [self getAppURLWithPath:REQUEST_ENDPOINT];
    DWORequest *oReq = [DWOClient requestTokenRequestFromURL:url consumer:tokenPair callback:@"oob"];
    [oReq setObject:@"true" forParameter:@"simple_verifier"];

    url = [oReq.url URLByAppendingQueryString:oReq.queryString];
    NSURLRequest *uReq = [NSURLRequest requestWithURL:url cachePolicy:NSURLCacheStorageNotAllowed timeoutInterval:30];
    
    AFHTTPRequestOperation *operation = [[AFHTTPRequestOperation alloc] initWithRequest:uReq];

    DWPendingAuthorization *pending = [[DWPendingAuthorization alloc]
            initWithClient:self operation:operation accessCallback:callback oobCallback:oobCallback];
    [pending start];
    [pending release];
    [operation release];
}

- (void)dealloc {
    [baseEndpoint release];
    baseEndpoint = nil;

    [tokenPair release];
    tokenPair = nil;

    [super dealloc];
}

@end

@implementation DWClient (Internal)

+(void)removePendingAuthorization:(DWPendingAuthorization*)auth {
    
}

@end
