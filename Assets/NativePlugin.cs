using System;

using UnityEngine;

using TMPro;

using Newtonsoft.Json.Linq;

public class NativePlugin : MonoBehaviour
{
    public TMP_Text text;
    public void Start()
    {
        string publicKey = CryptoKey.GetPublicKey();
        text.text = "GetPublicKey\n" + publicKey;
        if(string.IsNullOrEmpty(publicKey))
        {
            publicKey = CryptoKey.GeneratePublicKey();
            text.text = "GeneratePublicKey\n" + publicKey;
        }

        text.text += "\n\n" + CryptoKey.SignRawJsonToJWTES256(new JObject() {
            ["Test"] = DateTimeOffset.Now.ToString(),
        }.ToString());

        Debug.Log(text.text);
    }

    public void Clear()
    {
        CryptoKey.ClearPublicKey();
        text.text = "";
    }
}
