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
 
 //.h ile containing information about the client and connection details

#import <Foundation/Foundation.h>

@class DWOTokenPair;
@class DWORequest;
@class DWPendingAuthorization;

typedef void (^DWAccessTokenCallback)(bool success, DWOTokenPair *pair);
typedef void (^DWBeginAccessTokenCallback)(DWPendingAuthorization * auth, NSURL *url);

//interface for the connection between the client and object interface.
@interface DWClient : NSObject {
    @private
    NSString *baseEndpoint;
    BOOL sslEnabled;
    DWOTokenPair *tokenPair;

    NSString *appProtocol;
}

//properties for the connection protocols
@property (nonatomic,readonly,copy) NSString *baseEndpoint;
@property (nonatomic,readonly,assign) BOOL sslEnabled;
@property (nonatomic,readwrite,copy) NSString *appProtocol;

- (id)initWithEndpoint:(NSString*)endpoint ssl:(BOOL)ssl tokenPair:(DWOTokenPair*)tokenPair;

- (void)setAppProtocol:(NSString*)protocol;

- (NSURL *)getAppURLWithPath:(NSString*)path;

//authorization functions
- (void)authorizeUser:(DWAccessTokenCallback)callback begin:(DWBeginAccessTokenCallback)beginCallback;
- (void)authorizeUser:(DWAccessTokenCallback)callback outOfBand:(DWBeginAccessTokenCallback)oobCallback;

-(BOOL)maybeHandleOpenURL:(NSURL *)url;

@end
