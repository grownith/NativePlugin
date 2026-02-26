package com.grownith.unityplugin;

import android.util.Log;
import android.util.Base64;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyGenParameterSpec;

import java.nio.charset.StandardCharsets;

import java.security.*;
import java.security.interfaces.ECPublicKey;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.crypto.ECDSASigner;

public class KeyStoreWrapper {
    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";

    /**
     * Generate RSA key pair and AES256 key, encrypt and store the public key.
     * @return Base64-encoded encrypted public key or error message
     */
    public static String generateKeystorePublicKeyWithAES256(String keyAlias, String aesAlias) {
        try {
            var kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER);
            kpg.initialize(new KeyGenParameterSpec.Builder(
                    keyAlias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256,KeyProperties.DIGEST_SHA512)
                    .build());

            Log.i("kpg",kpg.toString());
            var keyPair = kpg.generateKeyPair();
            var publicKey = (ECPublicKey)keyPair.getPublic();

            return new ECKey.Builder(Curve.forECParameterSpec(publicKey.getParams()),publicKey)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyIDFromThumbprint()
                    .build().toJSONString();
        } catch (Exception e) {
            Log.e("generateKeystorePublicKeyWithAES256",e.toString());
            return "error: " + e.getMessage();
        }
    }

    /**
     * Decrypt and retrieve the public key.
     * @return Base64-encoded decrypted public key (X.509 format) or empty string on error
     */
    public static String getKeystorePublicKey(String keyAlias) {
        try {
            var ks = KeyStore.getInstance(KEYSTORE_PROVIDER);
            ks.load(null);

            var cert = ks.getCertificate(keyAlias);
            var publicKey = (ECPublicKey)cert.getPublicKey();
            return getPublicKeyECKey(publicKey).toJSONString();
        } catch (Exception e) {
            Log.e("UnityPlugin", "Error retrieving encrypted public key: " + e.getMessage());
            return "";
        }
    }

    static ECKey getPublicKeyECKey(ECPublicKey publicKey) throws Exception {
        return new ECKey.Builder(Curve.forECParameterSpec(publicKey.getParams()),publicKey)
                .keyUse(KeyUse.SIGNATURE)
                .keyIDFromThumbprint()
                .build();
    }

    /**
     * Clear the stored encrypted public key.
     * @return "success" or error message
     */
    public static String clearKeystorePublicKey(String keyAlias) {
        try {
            var ks = KeyStore.getInstance(KEYSTORE_PROVIDER);
            ks.load(null);
            ks.deleteEntry(keyAlias);
            return "success";
        } catch (Exception e) {
            return "error: " + e.getMessage();
        }
    }

    /**
     * Sign JSON payload to create a JWT token using ES256 (ECDSA with SHA-256).
     * Uses RSA private key stored in Android KeyStore.
     * @param jsonPayload Base64-encoded JSON payload
     * @return Base64-encoded JWT token (header.payload.signature) or error message
     */
    public static String signJsonToJWTES256(String jsonPayload, String keyAlias) {
        try {
            if (jsonPayload == null || jsonPayload.isEmpty()) {
                return "error: jsonPayload cannot be null or empty";
            }

            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);

            if (!keyStore.containsAlias(keyAlias)) {
                return "error: RSA key not found. Generate keystore first.";
            }

            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, null);
            if (privateKey == null) {
                return "error: failed to retrieve private key";
            }

            var cert = keyStore.getCertificate(keyAlias);
            var publicKey = (ECPublicKey)cert.getPublicKey();
            var signer = new ECDSASigner(privateKey,Curve.forECParameterSpec(publicKey.getParams()));
            var jwsObject = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(getPublicKeyECKey(publicKey).computeThumbprint().toString()).build(),new Payload(Base64URL.from(jsonPayload)));
            jwsObject.sign(signer);
            return jwsObject.serialize();
        } catch (Exception e) {
            return "error: " + e.getMessage();
        }
    }

    /**
     * Sign raw JSON string to JWT using ES256 (will be Base64-encoded internally).
     * @param rawJsonPayload Raw JSON string
     * @return Base64-encoded JWT token or error message
     */
    public static String signRawJsonToJWTES256(String rawJsonPayload, String keyAlias) {
        try {
            if (rawJsonPayload == null || rawJsonPayload.isEmpty()) {
                return "error: rawJsonPayload cannot be null or empty";
            }

            // Base64-encode the payload
            String encodedPayload = Base64.encodeToString(rawJsonPayload.getBytes(StandardCharsets.UTF_8),Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
            return signJsonToJWTES256(encodedPayload, keyAlias);
        } catch (Exception e) {
            return "error: " + e.getMessage();
        }
    }
}
