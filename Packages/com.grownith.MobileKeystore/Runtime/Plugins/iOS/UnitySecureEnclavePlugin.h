#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface UnitySecureEnclavePlugin : NSObject

// Generate a new EC key pair in Secure Enclave and return Base64 public key
// `label` specifies the key label to use in the Keychain
+ (NSString *)generateSecureEnclavePublicKey:(NSString *)label;

// Retrieve the public key from Keychain (Base64 encoded)
// `label` specifies the key label to look up
+ (NSString *)getSecureEnclavePublicKey:(NSString *)label;

// Clear the public key from Keychain
// `label` specifies the key label to remove
+ (NSString *)clearSecureEnclavePublicKey:(NSString *)label;

// Sign JSON payload to create a JWT token with ES256
// `label` specifies which private key in the Keychain to use
+ (NSString *)signJsonToJWTES256:(NSString *)jsonPayload label:(NSString *)label;

// Sign raw JSON string to JWT with ES256 (will be Base64-encoded internally)
// `label` specifies which private key in the Keychain to use
+ (NSString *)signRawJsonToJWTES256:(NSString *)rawJsonPayload label:(NSString *)label;

@end

NS_ASSUME_NONNULL_END
