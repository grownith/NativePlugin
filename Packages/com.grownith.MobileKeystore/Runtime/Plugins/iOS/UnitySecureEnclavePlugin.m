#import "UnitySecureEnclavePlugin.h"
#import <Security/Security.h>
#import <stdlib.h>
#import <CommonCrypto/CommonCrypto.h>

#ifdef __cplusplus
extern "C" {
#endif

// Helper for Base64URL encoding
static NSString *base64UrlEncodeString(NSString *base64) {
    base64 = [base64 stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
    base64 = [base64 stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    base64 = [base64 stringByReplacingOccurrencesOfString:@"=" withString:@""];
    return base64;
}

static NSString *base64UrlEncode(NSData *data) {
    NSString *base64 = [data base64EncodedStringWithOptions:0];
    return base64UrlEncodeString(base64);
}

// Convert SecKeyRef public key to JWK JSON string (Base64URL encoded)
static const char *jwkJsonStringFromSecKey(SecKeyRef key) {
    CFErrorRef error = NULL;
    NSData *keyData = (__bridge_transfer NSData *)SecKeyCopyExternalRepresentation(key, &error);

    if (!keyData || keyData.length != 65) {
        if (error) CFRelease(error);
        return strdup("");
    }

    // 1. Extract X and Y (Skip the 0x04 prefix at index 0)
    NSData *xData = [keyData subdataWithRange:NSMakeRange(1, 32)];
    NSData *yData = [keyData subdataWithRange:NSMakeRange(33, 32)];

    // 2. Build the Dictionary
    NSDictionary *jwkDict = @{
        @"kty": @"EC",
        @"crv": @"P-256",
        @"x": base64UrlEncode(xData),
        @"y": base64UrlEncode(yData),
        @"use": @"sig",
        @"alg": @"ES256"
    };

    // 3. Serialize to JSON Data
    NSError *jsonError = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:jwkDict
                                                       options:0
                                                         error:&jsonError];

    if (!jsonData) return strdup("");

    // 4. Convert to NSString then to const char*
    NSString *jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    const char *utf = [jsonString UTF8String];
    return utf ? strdup(utf) : strdup("");
}

// Compute JWK thumbprint (RFC 7638) from SecKey public key
static NSString *jwkThumbprintFromSecKey(SecKeyRef key) {
    CFErrorRef error = NULL;
    NSData *keyData = (__bridge_transfer NSData *)SecKeyCopyExternalRepresentation(key, &error);

    if (!keyData || keyData.length != 65) {
        if (error) CFRelease(error);
        return @"";
    }

    NSData *xData = [keyData subdataWithRange:NSMakeRange(1, 32)];
    NSData *yData = [keyData subdataWithRange:NSMakeRange(33, 32)];

    NSString *x = base64UrlEncode(xData);
    NSString *y = base64UrlEncode(yData);

    NSString *jwk = [NSString stringWithFormat:@"{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%@\",\"y\":\"%@\"}", x, y];

    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(jwk.UTF8String, (CC_LONG)[jwk lengthOfBytesUsingEncoding:NSUTF8StringEncoding], hash);
    NSData *hashData = [NSData dataWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];

    return base64UrlEncode(hashData);
}

static NSData *transcodeDERToRaw(NSData *derData) {
    // This is a simplified parser for a standard P-256 DER signature
    // A production version should strictly check ASN.1 tags (0x30, 0x02)
    const uint8_t *bytes = (const uint8_t *)derData.bytes;
    NSInteger length = derData.length;

    // Standard DER: 0x30 [len] 0x02 [R_len] [R] 0x02 [S_len] [S]
    // We need to find the offsets for R and S

    NSInteger rOffset = 4;
    NSInteger rLen = bytes[3];
    if (bytes[3] > 32) { // Handle leading zero byte padding
        rOffset += (rLen - 32);
        rLen = 32;
    }

    NSInteger sLenOffset = 4 + bytes[3] + 1;
    NSInteger sLen = bytes[sLenOffset];
    NSInteger sOffset = sLenOffset + 1;
    if (sLen > 32) { // Handle leading zero byte padding
        sOffset += (sLen - 32);
        sLen = 32;
    }

    NSMutableData *raw = [NSMutableData dataWithLength:64];
    uint8_t *rawBytes = (uint8_t *)raw.mutableBytes;

    // Copy R (right-aligned to 32 bytes)
    [derData getBytes:rawBytes + (32 - rLen) range:NSMakeRange(rOffset, rLen)];
    // Copy S (right-aligned to 32 bytes)
    [derData getBytes:rawBytes + 32 + (32 - sLen) range:NSMakeRange(sOffset, sLen)];

    return raw;
}

const char* generateSecureEnclavePublicKey(const char* label) {
    @autoreleasepool {
        @try {
            NSString *nsLabel = label ? [NSString stringWithUTF8String:label] : @"";
            NSError *error = nil;

            // Delete existing key if present
            NSDictionary *deleteQuery = @{
                (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                (__bridge id)kSecAttrLabel: nsLabel
            };
            SecItemDelete((__bridge CFDictionaryRef)deleteQuery);

            // Generate EC key pair in Secure Enclave (iOS 9+)
            NSMutableDictionary *keyAttrs = [@{
                (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeEC,
                (__bridge id)kSecAttrKeySizeInBits: @256,
                (__bridge id)kSecAttrLabel: nsLabel,
                (__bridge id)kSecPrivateKeyAttrs: @{
                    (__bridge id)kSecAttrIsPermanent: @YES,
                    (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                }
            } mutableCopy];

            // Use Secure Enclave (requires macOS 10.12+ or iOS 9+)
            if (@available(iOS 9.0, *)) {
                keyAttrs[(__bridge id)kSecAttrTokenID] = (__bridge id)kSecAttrTokenIDSecureEnclave;
            }

            SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFMutableDictionaryRef)keyAttrs, (void *)&error);

            if (!privateKey) {
                NSString *result = [NSString stringWithFormat:@"error: %@", error.description];
                const char *utf = [result UTF8String];
                return utf ? strdup(utf) : strdup("");
            }

            SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
            if (!publicKey) {
                CFRelease(privateKey);
                return strdup("error: failed to extract public key");
            }

            @try {
                return jwkJsonStringFromSecKey(publicKey);
            }
            @finally {
                CFRelease(publicKey);
                CFRelease(privateKey);
            }
        } @catch (NSException *e) {
            NSString *result = [NSString stringWithFormat:@"error: %@", e.reason];
            const char *utf = [result UTF8String];
            return utf ? strdup(utf) : strdup("");
        }
    }
}

const char* getSecureEnclavePublicKey(const char* label) {
    @autoreleasepool {
        @try {
            NSString *nsLabel = label ? [NSString stringWithUTF8String:label] : @"";

            NSDictionary *query = @{
                (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                (__bridge id)kSecAttrLabel: nsLabel,
                (__bridge id)kSecReturnRef: @YES
            };

            SecKeyRef publicKey = NULL;
            OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&publicKey);

            if (status != errSecSuccess || !publicKey) {
                return strdup("");
            }

            // Extract public key from the private key if needed
            SecKeyRef actualPublicKey = SecKeyCopyPublicKey(publicKey);
            if (!actualPublicKey) {
                CFRelease(publicKey);
                return strdup("");
            }

            @try {
                return jwkJsonStringFromSecKey(actualPublicKey);
            }
            @finally {
                CFRelease(publicKey);
                CFRelease(actualPublicKey);
            }
        } @catch (NSException *e) {
            NSLog(@"Error retrieving Secure Enclave public key: %@", e.reason);
            return strdup("");
        }
    }
}

const char* clearSecureEnclavePublicKey(const char* label) {
    @autoreleasepool {
        @try {
            NSString *nsLabel = label ? [NSString stringWithUTF8String:label] : @"";

            NSDictionary *deleteQuery = @{
                (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                (__bridge id)kSecAttrLabel: nsLabel
            };

            OSStatus status = SecItemDelete((__bridge CFDictionaryRef)deleteQuery);
            NSString *result = (status == errSecSuccess) ? @"success" : [NSString stringWithFormat:@"error: %d", (int)status];
            const char *utf = [result UTF8String];
            return utf ? strdup(utf) : strdup("");
        } @catch (NSException *e) {
            NSString *result = [NSString stringWithFormat:@"error: %@", e.reason];
            const char *utf = [result UTF8String];
            return utf ? strdup(utf) : strdup("");
        }
    }
}

const char* signJsonToJWTES256(const char* jsonPayload, const char* label) {
    @autoreleasepool {
        @try {
            NSString *nsPayload = jsonPayload ? [NSString stringWithUTF8String:jsonPayload] : @"";
            NSString *nsLabel = label ? [NSString stringWithUTF8String:label] : @"";

            if (!nsPayload || [nsPayload length] == 0) {
                return strdup("error: jsonPayload cannot be null or empty");
            }

            // Retrieve private key from Secure Enclave
            NSDictionary *query = @{
                (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                (__bridge id)kSecAttrLabel: nsLabel,
                (__bridge id)kSecReturnRef: @YES
            };

            SecKeyRef privateKey = NULL;
            OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&privateKey);

            if (status != errSecSuccess || !privateKey) {
                return strdup("error: private key not found. Generate Secure Enclave key first.");
            }

            SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
            NSString *kid = @"";
            if (publicKey) {
                kid = jwkThumbprintFromSecKey(publicKey);
                CFRelease(publicKey);
            }

            NSString *headerJson = [NSString stringWithFormat:@"{\"alg\":\"ES256\",\"typ\":\"JWT\",\"kid\":\"%@\"}", kid];
            NSData *headerData = [headerJson dataUsingEncoding:NSUTF8StringEncoding];
            NSString *header = base64UrlEncode(headerData);
            nsPayload = base64UrlEncodeString(nsPayload);

            NSString *signatureInput = [NSString stringWithFormat:@"%@.%@", header, nsPayload];
            NSData *signatureInputData = [signatureInput dataUsingEncoding:NSUTF8StringEncoding];

            CFErrorRef signError = NULL;
            CFDataRef signatureData = SecKeyCreateSignature(privateKey, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, (__bridge CFDataRef)signatureInputData, &signError);

            if (!signatureData) {
                CFRelease(privateKey);
                return strdup("error: failed to sign jwt");
            }

            signatureInputData = transcodeDERToRaw((__bridge NSData *)signatureData);

            NSString *signature = base64UrlEncode(signatureInputData);

            NSString *result = [NSString stringWithFormat:@"%@.%@.%@", header, nsPayload, signature];

            CFRelease(signatureData);
            CFRelease(privateKey);

            const char *utf = [result UTF8String];
            return utf ? strdup(utf) : strdup("");
        } @catch (NSException *e) {
            NSString *result = [NSString stringWithFormat:@"error: %@", e.reason];
            const char *utf = [result UTF8String];
            return utf ? strdup(utf) : strdup("");
        }
    }
}

const char* signRawJsonToJWTES256(const char* rawJsonPayload, const char* label) {
    @autoreleasepool {
        @try {
            NSString *nsPayload = rawJsonPayload ? [NSString stringWithUTF8String:rawJsonPayload] : @"";
            NSString *nsLabel = label ? [NSString stringWithUTF8String:label] : @"";

            if (!nsPayload || [nsPayload length] == 0) {
                return strdup("error: rawJsonPayload cannot be null or empty");
            }

            NSData *payloadData = [nsPayload dataUsingEncoding:NSUTF8StringEncoding];
            NSString *encodedPayload = [payloadData base64EncodedStringWithOptions:0];
            encodedPayload = [encodedPayload stringByReplacingOccurrencesOfString:@"=" withString:@""];

            return signJsonToJWTES256([encodedPayload UTF8String], [nsLabel UTF8String]);
        } @catch (NSException *e) {
            NSString *result = [NSString stringWithFormat:@"error: %@", e.reason];
            const char *utf = [result UTF8String];
            return utf ? strdup(utf) : strdup("");
        }
    }
}

#ifdef __cplusplus
}
#endif
