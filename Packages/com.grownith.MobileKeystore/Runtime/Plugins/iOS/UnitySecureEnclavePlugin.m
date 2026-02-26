#import "UnitySecureEnclavePlugin.h"
#import <Security/Security.h>

@implementation UnitySecureEnclavePlugin

#pragma mark - Secure Enclave & Keychain Methods

+ (NSString *)generateSecureEnclavePublicKey:(NSString *)label {
    @try {
        NSError *error = nil;

        // Delete existing key if present
        NSDictionary *deleteQuery = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassKey,
            (__bridge id)kSecAttrLabel: label
        };
        SecItemDelete((__bridge CFDictionaryRef)deleteQuery);

        // Generate EC key pair in Secure Enclave (iOS 9+)
        NSMutableDictionary *keyAttrs = [@{
            (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeEC,
            (__bridge id)kSecAttrKeySizeInBits: @256,
            (__bridge id)kSecAttrLabel: label,
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
            return [NSString stringWithFormat:@"error: %@", error.description];
        }

        SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
        if (!publicKey) {
            CFRelease(privateKey);
            return @"error: failed to extract public key";
        }

        // Export public key to PKCS#1 format (X.509)
        CFErrorRef exportError = NULL;
        CFDataRef publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &exportError);

        if (!publicKeyData) {
            CFRelease(publicKey);
            CFRelease(privateKey);
            return @"error: failed to export public key";
        }

        // Base64 encode
        NSString *publicKeyBase64 = [(__bridge NSData *)publicKeyData base64EncodedStringWithOptions:0];

        // Cleanup
        CFRelease(publicKeyData);
        CFRelease(publicKey);
        CFRelease(privateKey);

        return publicKeyBase64;
    } @catch (NSException *e) {
        return [NSString stringWithFormat:@"error: %@", e.reason];
    }
}

+ (NSString *)getSecureEnclavePublicKey:(NSString *)label {
    @try {
        NSDictionary *query = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassKey,
            (__bridge id)kSecAttrLabel: label,
            (__bridge id)kSecReturnRef: @YES
        };

        SecKeyRef publicKey = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&publicKey);

        if (status != errSecSuccess || !publicKey) {
            return @"";
        }

        // Extract public key from the private key if needed
        SecKeyRef actualPublicKey = SecKeyCopyPublicKey(publicKey);
        if (!actualPublicKey) {
            CFRelease(publicKey);
            return @"";
        }

        CFErrorRef exportError = NULL;
        CFDataRef publicKeyData = SecKeyCopyExternalRepresentation(actualPublicKey, &exportError);

        if (!publicKeyData) {
            CFRelease(actualPublicKey);
            CFRelease(publicKey);
            return @"";
        }

        NSString *publicKeyBase64 = [(__bridge NSData *)publicKeyData base64EncodedStringWithOptions:0];

        // Cleanup
        CFRelease(publicKeyData);
        CFRelease(actualPublicKey);
        CFRelease(publicKey);

        return publicKeyBase64;
    } @catch (NSException *e) {
        NSLog(@"Error retrieving Secure Enclave public key: %@", e.reason);
        return @"";
    }
}

+ (NSString *)clearSecureEnclavePublicKey:(NSString *)label {
    @try {
        NSDictionary *deleteQuery = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassKey,
            (__bridge id)kSecAttrLabel: label
        };

        OSStatus status = SecItemDelete((__bridge CFDictionaryRef)deleteQuery);
        return (status == errSecSuccess) ? @"success" : [NSString stringWithFormat:@"error: %d", (int)status];
    } @catch (NSException *e) {
        return [NSString stringWithFormat:@"error: %@", e.reason];
    }
}

#pragma mark - JWT Signing Methods (ES256)

+ (NSString *)signJsonToJWTES256:(NSString *)jsonPayload label:(NSString *)label {
    @try {
        if (!jsonPayload || [jsonPayload length] == 0) {
            return @"error: jsonPayload cannot be null or empty";
        }

        // Retrieve private key from Secure Enclave
        NSDictionary *query = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassKey,
            (__bridge id)kSecAttrLabel: label,
            (__bridge id)kSecReturnRef: @YES
        };

        SecKeyRef privateKey = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&privateKey);

        if (status != errSecSuccess || !privateKey) {
            return @"error: private key not found. Generate Secure Enclave key first.";
        }

        // Create JWT header for ES256
        NSString *headerJson = @"{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
        NSData *headerData = [headerJson dataUsingEncoding:NSUTF8StringEncoding];
        NSString *header = [headerData base64EncodedStringWithOptions:0];
        header = [header stringByReplacingOccurrencesOfString:@"=" withString:@""];
        header = [header stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
        header = [header stringByReplacingOccurrencesOfString:@"/" withString:@"_"];

        // Prepare payload (assume already Base64-encoded)
        NSString *payload = [jsonPayload stringByReplacingOccurrencesOfString:@"=" withString:@""];
        payload = [payload stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
        payload = [payload stringByReplacingOccurrencesOfString:@"/" withString:@"_"];

        // Create signature
        NSString *signatureInput = [NSString stringWithFormat:@"%@.%@", header, payload];
        NSData *signatureInputData = [signatureInput dataUsingEncoding:NSUTF8StringEncoding];

        CFErrorRef signError = NULL;
        CFDataRef signatureData = SecKeyCreateSignature(privateKey, kSecKeyAlgorithmECDSASHA256, (__bridge CFDataRef)signatureInputData, &signError);

        if (!signatureData) {
            CFRelease(privateKey);
            return @"error: failed to sign jwt";
        }

        NSString *signature = [(__bridge NSData *)signatureData base64EncodedStringWithOptions:0];
        signature = [signature stringByReplacingOccurrencesOfString:@"=" withString:@""];
        signature = [signature stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
        signature = [signature stringByReplacingOccurrencesOfString:@"/" withString:@"_"];

        CFRelease(signatureData);
        CFRelease(privateKey);

        return [NSString stringWithFormat:@"%@.%@.%@", header, payload, signature];
    } @catch (NSException *e) {
        return [NSString stringWithFormat:@"error: %@", e.reason];
    }
}

+ (NSString *)signRawJsonToJWTES256:(NSString *)rawJsonPayload label:(NSString *)label {
    @try {
        if (!rawJsonPayload || [rawJsonPayload length] == 0) {
            return @"error: rawJsonPayload cannot be null or empty";
        }

        NSData *payloadData = [rawJsonPayload dataUsingEncoding:NSUTF8StringEncoding];
        NSString *encodedPayload = [payloadData base64EncodedStringWithOptions:0];
        encodedPayload = [encodedPayload stringByReplacingOccurrencesOfString:@"=" withString:@"" ];

        return [UnitySecureEnclavePlugin signJsonToJWTES256:encodedPayload label:label];
    } @catch (NSException *e) {
        return [NSString stringWithFormat:@"error: %@", e.reason];
    }
}

@end
