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

#import "DWOClient.h"
#import "DWORequest.h"

@implementation DWOClient

+(NSString *) encodeString:(NSString*)string {
    return [self encodeData:[string dataUsingEncoding:NSUTF8StringEncoding]];
}

// FIXME: there may be a better way to do this.
+(NSString *) encodeData:(NSData*)data {
    size_t len = [data length];
    unsigned char *rawData = (unsigned char *)[data bytes];
    char *outBuffer = (char *)malloc( (len * 3)+8 );
    char *outPtr = outBuffer;

    if ( outBuffer == 0 ) return nil;

    for ( size_t i = 0; i < len; ++i ) {
        unsigned char c = rawData[i];
        if ( isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~' ) {
            *(outPtr++) = (char)c;
        } else {
            snprintf(outPtr,4,"%%%02X",c);
            outPtr += 3;
        }
    }
    *(outPtr) = 0;

    NSString *rv = [NSString stringWithUTF8String:outBuffer];
    free( outBuffer );

    return rv;
}

+(NSString *) encodeObject:(id)object {
    if ( object == nil ) {
        return nil;
    } else if ( [object isKindOfClass:[NSString class]] ) {
        return [DWOClient encodeString:object];
    } else if ( [object isKindOfClass:[NSData class]] ) {
        return [DWOClient encodeData:object];
    } else if ( [object isKindOfClass:[NSNumber class]] ) {
        return [object stringValue]; 
    } else {
        return [DWOClient encodeString:[object stringValue]];
    }
}

+(DWORequest *) requestTokenRequestFromURL:(NSURL*)url consumer:(DWOTokenPair*)consumerPair callback:(NSString*)callback; {
    DWORequest *req = [[[DWORequest alloc] initWithURL:url consumerToken:consumerPair method:@"GET"] autorelease];
    [req setObject:callback forOAuthParameter:@"oauth_callback"];
    return req;
}

+(NSString *) createRandomStringOfLength:(size_t)len {
    static const char letter_set[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_";
    static const size_t letter_set_len = sizeof(letter_set)-1;
    char *data = (char*)malloc(len+1);
    if ( data == 0 ) return nil;
    data[len] = 0;
    
    for ( int i = 0; i < len; ++i )
        data[i] = letter_set[arc4random() % letter_set_len];

    NSString *rv = [NSString stringWithCString:data encoding:NSASCIIStringEncoding];
    free( data );

    return rv;
}

@end
