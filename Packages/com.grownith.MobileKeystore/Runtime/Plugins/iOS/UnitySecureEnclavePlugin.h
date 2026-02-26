#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Generate a new EC key pair in Secure Enclave and return Base64 public key
// `label` specifies the key label to use in the Keychain
const char* generateSecureEnclavePublicKey(const char* label);

// Retrieve the public key from Keychain (Base64 encoded)
// `label` specifies the key label to look up
const char* getSecureEnclavePublicKey(const char* label);

// Clear the public key from Keychain
// `label` specifies the key label to remove
const char* clearSecureEnclavePublicKey(const char* label);

// Sign JSON payload to create a JWT token with ES256
// `label` specifies which private key in the Keychain to use
const char* signJsonToJWTES256(const char* jsonPayload, const char* label);

// Sign raw JSON string to JWT with ES256 (will be Base64-encoded internally)
// `label` specifies which private key in the Keychain to use
const char* signRawJsonToJWTES256(const char* rawJsonPayload, const char* label);

#ifdef __cplusplus
}
#endif
