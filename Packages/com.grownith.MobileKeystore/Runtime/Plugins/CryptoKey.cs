using System;
using System.Runtime.InteropServices;
using UnityEngine;

public static class CryptoKey {
#if UNITY_IOS
    [DllImport("__Internal")]
    private static extern string generateSecureEnclavePublicKey(string label);

    [DllImport("__Internal")]
    private static extern string getSecureEnclavePublicKey(string label);

    [DllImport("__Internal")]
    private static extern string clearSecureEnclavePublicKey(string label);

    [DllImport("__Internal")]
    private static extern string signJsonToJWTES256(string jsonPayload, string label);

    [DllImport("__Internal")]
    private static extern string signRawJsonToJWTES256(string rawJsonPayload, string label);

    const string defaultLabel = "com.grownith.unity.enclave.key";
    public static string GeneratePublicKey(string label = defaultLabel) {
        return generateSecureEnclavePublicKey(label);
    }

    public static string GetPublicKey(string label = defaultLabel) {
        return getSecureEnclavePublicKey(label);
    }

    public static string ClearPublicKey(string label = defaultLabel) {
        return clearSecureEnclavePublicKey(label);
    }

    public static string SignJsonToJWTES256(string jsonPayload, string label = defaultLabel) {
        return signJsonToJWTES256(jsonPayload, label);
    }

    public static string SignRawJsonToJWTES256(string rawJsonPayload, string label = defaultLabel) {
        return signRawJsonToJWTES256(rawJsonPayload, label);
    }
#endif

#if UNITY_ANDROID
    private static AndroidJavaClass plugin = new AndroidJavaClass("com.grownith.unityplugin.KeyStoreWrapper");

    const string defaultLabel = "unity_plugin_keystore";
    public static string GeneratePublicKey(string keyAlias = defaultLabel) {
        Debug.Assert(plugin != null,"null plugin");
        return plugin.CallStatic<string>("generateKeystorePublicKeyWithAES256", keyAlias, "unity_aes256_key");
    }

    public static string GetPublicKey(string keyAlias = defaultLabel) {
        Debug.Assert(plugin != null,"null plugin");
        return plugin.CallStatic<string>("getKeystorePublicKey", keyAlias);
    }

    public static string ClearPublicKey(string keyAlias = defaultLabel) {
        Debug.Assert(plugin != null,"null plugin");
        return plugin.CallStatic<string>("clearKeystorePublicKey", keyAlias);
    }

    public static string SignJsonToJWTES256(string jsonPayload, string keyAlias = defaultLabel) {
        Debug.Assert(plugin != null,"null plugin");
        return plugin.CallStatic<string>("signJsonToJWTES256", jsonPayload, keyAlias);
    }

    public static string SignRawJsonToJWTES256(string rawJsonPayload, string keyAlias = defaultLabel) {
        Debug.Assert(plugin != null,"null plugin");
        return plugin.CallStatic<string>("signRawJsonToJWTES256", rawJsonPayload, keyAlias);
    }
#endif

}