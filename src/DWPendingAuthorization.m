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

#import "DWPendingAuthorization.h"
#import "AFHTTPRequestOperation.h"

#import "DWClient.h"
#import "DWClient+Internal.h"
#import "NSString+QueryString.h"

#import "DWOClient.h"
#import "DWOTokenPair.h"

static const NSTimeInterval VALIDITY = 600 * 2; // Double the valididty.

static NSMutableDictionary *pendingAuthorizations = nil;

@implementation DWPendingAuthorization

+(void)initialize {
    pendingAuthorizations = [[NSMutableDictionary alloc] init];
}

-(id)initWithClient:(DWClient*)client_ operation:(AFHTTPRequestOperation*)op
     accessCallback:(DWAccessTokenCallback)access_
      beginCallback:(DWBeginAccessTokenCallback)begin_
          outOfBand:(BOOL)oob_ {

    if ( ( self = [super init] ) ) {
        client = [client_ retain];
        outOfBand = oob_;
        operation = [op retain];
        accessCallback = access_ ? Block_copy(access_) : nil;
        beginCallback = begin_ ? Block_copy(begin_) : nil;
        requestToken = nil;
        valid = NO;
        expireTimer = nil;

        [operation setCompletionBlockWithSuccess:^(AFHTTPRequestOperation *iOp_, id responseObject) {
            if ( beginCallback == nil || accessCallback == nil ) {
                [self release];
                return;
            }

            if ( ! [responseObject isKindOfClass:[NSData class]] ) {
                accessCallback(YES,nil);
                [self release];
                return;
            }
            NSData *dv = (NSData*)responseObject;
            NSString *sv = [[NSString alloc] initWithData:dv encoding:NSUTF8StringEncoding];
            NSDictionary *args = [sv dictionaryFromQueryString];
            [sv release];

            NSString *arg = [args objectForKey:@"oauth_callback_confirmed"];

            if ( arg == nil || [arg compare:@"true"] != NSOrderedSame ) {
                if ( accessCallback != nil ) accessCallback(YES, nil);
                [self release];
                return;
            }

            NSData *token, *secret;
            arg = [args objectForKey:@"oauth_token"];
            if ( arg == nil ) {
                accessCallback(YES,nil);
                [self release];
                return;
            }
            token = [arg dataUsingEncoding:NSUTF8StringEncoding];
            
            arg = [args objectForKey:@"oauth_token_secret"];
            if ( arg == nil ) {
                accessCallback(YES, nil);
                [self release];
                return;
            }
            secret = [arg dataUsingEncoding:NSUTF8StringEncoding];

            self->requestToken = [[DWOTokenPair alloc] initWithToken:token secret:secret];
            valid = YES;

            if ( !outOfBand )
                [pendingAuthorizations setObject:self forKey:[DWOClient encodeData:requestToken.token]];

            NSURL *url = [client authorizeURLForToken:requestToken];
            expireTimer = [[NSTimer scheduledTimerWithTimeInterval:VALIDITY
                                                            target:self
                                                          selector:@selector(tokenExpired:)
                                                          userInfo:nil repeats:NO] retain];

            [operation release];
            operation = nil;

            beginCallback(self,url);
        } failure:^(AFHTTPRequestOperation *iOp_, NSError *error) {            
            [operation release];
            operation = nil;

            if ( accessCallback != nil )
                accessCallback(YES,nil);
            [self release];
        }];
    }
    return self;
}

-(void)tokenExpired:(NSTimer*)theTimer {
    valid = NO;
    if ( requestToken )
        [pendingAuthorizations removeObjectForKey:[DWOClient encodeData:requestToken.token]];
    if ( accessCallback != nil )
        accessCallback(YES,nil);
    [expireTimer release];
    expireTimer = nil;
}

-(void)start {
    // This holds a copy to itself while it's running
    [self retain];

    [operation start];
}

-(void)abort {
    if ( accessCallback )
        Block_release(accessCallback);
    if ( beginCallback )
        Block_release(beginCallback);
    accessCallback = nil;
    beginCallback = nil;
    valid = NO;
}


+(void)gotVerifier:(NSString*)verifier forToken:(NSData*)token {
    DWPendingAuthorization *pend = [pendingAuthorizations objectForKey:[DWOClient encodeData:token]];
    if ( pend != nil ) [pend gotVerifier:verifier];
}

-(void)gotVerifier:(NSString*)verifier {
    if ( valid == NO )
        return;

    if ( requestToken )
        [pendingAuthorizations removeObjectForKey:[DWOClient encodeData:requestToken.token]];

    AFHTTPRequestOperation *op_ = [client accessTokenOperationWithRequest:requestToken andVerifier:verifier];
    if ( operation != nil ) {
        [operation release];
        operation = nil;
    }
    operation = [op_ retain];
    [operation setCompletionBlockWithSuccess:^(AFHTTPRequestOperation *iOp_, id responseObject) {
        if ( accessCallback == nil ) {
            [self release];
            return;
        }
        
        if ( ! [responseObject isKindOfClass:[NSData class]] ) {
            accessCallback(YES,nil);
            [self release];
            return;
        }
        NSData *dv = (NSData*)responseObject;
        NSString *sv = [[NSString alloc] initWithData:dv encoding:NSUTF8StringEncoding];
        NSDictionary *args = [sv dictionaryFromQueryString];
        [sv release];
        [self release];

        [operation release];
        operation = nil;
    } failure:^(AFHTTPRequestOperation *iOp_, NSError *error) {            
        [operation release];
        operation = nil;

        if ( accessCallback != nil )
            accessCallback(YES,nil);
        [self release];
    }];
    [operation start];
}

-(void)dealloc {
    if ( accessCallback )
        Block_release(accessCallback);
    if ( beginCallback )
        Block_release(beginCallback);
    accessCallback = nil;
    beginCallback = nil;

    if ( expireTimer ) {
        [expireTimer invalidate];
        [expireTimer release];
    }
    expireTimer = nil;

    [client release];
    [operation release];
    client = nil;
    operation = nil;
    
    if ( requestToken )
        [pendingAuthorizations removeObjectForKey:[DWOClient encodeData:requestToken.token]];

    [requestToken release];
    requestToken = nil;

    [super dealloc];
}

@end
