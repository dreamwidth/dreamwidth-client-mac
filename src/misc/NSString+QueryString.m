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

#import "NSString+QueryString.h"

@implementation NSString (QueryString)

//implementation of adding a query parameter to a url
// http://stackoverflow.com/questions/6309698/objective-c-how-to-add-query-parameter-to-nsurl
-(NSDictionary*)dictionaryFromQueryString {
    NSArray *components = [self componentsSeparatedByString:@"&"];
    NSMutableDictionary *rv = [NSMutableDictionary dictionaryWithCapacity:[components count]];
    
    for ( NSString *pairStr in components ) {
        NSArray *pair = [pairStr componentsSeparatedByString:@"="];
        NSString *part = [pair objectAtIndex:0];
        if ( part == nil || [part length] == 0 || [pair count] < 1 ) continue;
        NSString *key = [part stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];

        part = [pair count] > 1 ? [pair objectAtIndex:1] : @"";
        NSString *value = [part stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];

        [rv setObject:value forKey:key];
    }
    return [NSDictionary dictionaryWithDictionary:rv];
}

@end
