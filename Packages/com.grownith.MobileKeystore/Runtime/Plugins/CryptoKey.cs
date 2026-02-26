using System;
using System.Linq;
using UnityEngine;

#if UNITY_EDITOR
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
#else
using System.Runtime.InteropServices;
#endif

public static class CryptoKey
{
#if UNITY_EDITOR
    const string defaultLabel = "";
    static string ComputeJwkThumbprint(X509Certificate2 cert)
    {
        using var pub = cert.GetECDsaPublicKey();
        if (pub == null)
            throw new InvalidOperationException("Certificate does not contain an ECDSA public key.");

        var parameters = pub.ExportParameters(false);
        var x = Base64UrlEncode(parameters.Q.X);
        var y = Base64UrlEncode(parameters.Q.Y);

        var jwk = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(jwk));
        return Base64UrlEncode(hash);
    }
#elif UNITY_IOS
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
#elif UNITY_ANDROID
    private static AndroidJavaClass plugin = new AndroidJavaClass("com.grownith.unityplugin.KeyStoreWrapper");
    const string defaultLabel = "unity_plugin_keystore";
#endif

    public static string GeneratePublicKey(string keyAlias = defaultLabel)
    {
#if UNITY_EDITOR
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var subjectName = new X500DistinguishedName($"CN={keyAlias}");
        var request = new CertificateRequest(subjectName, ecdsa, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));

        var now = DateTimeOffset.UtcNow;
        now -= now.TimeOfDay;
        var certificate = request.CreateSelfSigned(now,now.AddYears(50));
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(certificate);
        store.Close();

        return certificate.GetPublicKeyString();
#elif UNITY_IOS
        return generateSecureEnclavePublicKey(keyAlias);
#elif UNITY_ANDROID
        Debug.Assert(plugin != null,"null plugin");
        return plugin.CallStatic<string>("generateKeystorePublicKeyWithAES256", keyAlias, "unity_aes256_key");
#endif
    }

#if UNITY_EDITOR
    static X509Certificate2 GetCert(string keyAlias)
    {
        var subjectName = new X500DistinguishedName($"CN={keyAlias}");
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        try
        {
            return store.Certificates.OfType<X509Certificate2>().FirstOrDefault((item) => item.SubjectName == subjectName);
        }
        finally
        {
            store.Close();
        }
    }
#endif

    public static string GetPublicKey(string keyAlias = defaultLabel)
    {
#if UNITY_EDITOR
        return GetCert(keyAlias).GetPublicKeyString();
#elif UNITY_IOS
        return getSecureEnclavePublicKey(keyAlias);
#elif UNITY_ANDROID
        Debug.Assert(plugin != null,"null plugin");
        return plugin.CallStatic<string>("getKeystorePublicKey", keyAlias);
#endif
    }

    public static string ClearPublicKey(string keyAlias = defaultLabel)
    {
#if UNITY_EDITOR
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var subjectName = new X500DistinguishedName($"CN={keyAlias}");
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        var certificate = store.Certificates.OfType<X509Certificate2>().FirstOrDefault((item) => item.SubjectName == subjectName);
        store.Remove(certificate);
        store.Close();

        return "";
#elif UNITY_IOS
        return clearSecureEnclavePublicKey(keyAlias);
#elif UNITY_ANDROID
        Debug.Assert(plugin != null,"null plugin");
        return plugin.CallStatic<string>("clearKeystorePublicKey", keyAlias);
#endif
    }

    static string Base64UrlEncode(byte[] input) => Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static string SignJsonToJWTES256(string jsonPayload, string keyAlias = defaultLabel)
    {
#if UNITY_EDITOR
        // header includes JWK thumbprint as kid
        var cert = GetCert(keyAlias);
        if (cert == null)
            throw new InvalidOperationException($"Certificate for alias '{keyAlias}' not found.");

        var kid = ComputeJwkThumbprint(cert);
        var header = $"{{\"alg\":\"ES256\",\"typ\":\"JWT\",\"kid\":\"{kid}\"}}";
        var encodedHeader = Base64UrlEncode(Encoding.UTF8.GetBytes(header));
        var encodedPayload = Base64UrlEncode(Encoding.UTF8.GetBytes(jsonPayload));
        var signingInput = encodedHeader + "." + encodedPayload;

        using var ecdsa = cert.GetECDsaPrivateKey();
        var signature = ecdsa.SignData(Encoding.UTF8.GetBytes(signingInput), HashAlgorithmName.SHA256);
        return signingInput + "." + Base64UrlEncode(signature);
#elif UNITY_IOS
        return signJsonToJWTES256(jsonPayload, keyAlias);
#elif UNITY_ANDROID
        Debug.Assert(plugin != null,"null plugin");
        return plugin.CallStatic<string>("signJsonToJWTES256", jsonPayload, keyAlias);
#endif
    }

    public static string SignRawJsonToJWTES256(string rawJsonPayload, string keyAlias = defaultLabel)
    {
#if UNITY_EDITOR
        // rawJsonPayload is expected to be already base64url-encoded; include kid and sign
        var cert = GetCert(keyAlias);
        if (cert == null)
            throw new InvalidOperationException($"Certificate for alias '{keyAlias}' not found.");

        var kid = ComputeJwkThumbprint(cert);
        var header = $"{{\"alg\":\"ES256\",\"typ\":\"JWT\",\"kid\":\"{kid}\"}}";
        var encodedHeader = Base64UrlEncode(Encoding.UTF8.GetBytes(header));
        var signingInput = encodedHeader + "." + rawJsonPayload;

        using var ecdsa = cert.GetECDsaPrivateKey();
        var signature = ecdsa.SignData(Encoding.UTF8.GetBytes(signingInput), HashAlgorithmName.SHA256);
        return signingInput + "." + Base64UrlEncode(signature);
#elif UNITY_IOS
        return signRawJsonToJWTES256(rawJsonPayload, keyAlias);
#elif UNITY_ANDROID
        Debug.Assert(plugin != null,"null plugin");
        return plugin.CallStatic<string>("signRawJsonToJWTES256", rawJsonPayload, keyAlias);
#endif
    }
}