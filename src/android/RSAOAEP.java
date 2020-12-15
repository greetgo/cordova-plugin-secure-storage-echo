package com.crypho.plugins;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyInfo;
import android.util.Log;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

public class RSAOAEP extends AbstractRSA {
    public Map keyPair = new HashMap<String, String>();
    public static String PUBLIC_KEY = "publicKey";
    public static String PRIVATE_KEY = "privateKey";

    @Override
    AlgorithmParameterSpec getInitParams(Context ctx, String alias, Integer userAuthenticationValidityDuration) throws Exception {
        return null;
    }

    @TargetApi(Build.VERSION_CODES.M)
    public boolean isEntryAvailable(String alias) {
        try {
            Key privateKey = loadKey(Cipher.DECRYPT_MODE, alias);
            if (privateKey == null) {
                return false;
            }
            KeyFactory factory = KeyFactory.getInstance(privateKey.getAlgorithm(), KEYSTORE_PROVIDER);
            KeyInfo keyInfo = factory.getKeySpec(privateKey, KeyInfo.class);
            return keyInfo.isInsideSecureHardware();
        } catch (Exception e) {
            Log.i(TAG, "Checking encryption keys failed.", e);
            return false;
        }
    }

    @Override
    public byte[] encrypt(byte[] buf, String alias) throws Exception {
        return CryptoUtil.encrypt(buf, (String) keyPair.get("publicKey"));
    }

    @Override
    public byte[] decrypt(byte[] buf, String alias) throws Exception {
        return CryptoUtil.decrypt(buf, (String) keyPair.get("privateKey"));
    }

    @Override
    public void createKeyPair(SharedPreferencesHandler storage) {
        String publicKey = storage.fetch(PUBLIC_KEY);
        String privateKey = storage.fetch(PRIVATE_KEY);
        if (publicKey == null || privateKey == null) {
            try {
                Map<String, String> keyPair = CryptoUtil.generateKeyPair();
                publicKey = keyPair.get(PUBLIC_KEY);
                privateKey = keyPair.get(PRIVATE_KEY);
                storage.store(PUBLIC_KEY, publicKey);
                storage.store(PRIVATE_KEY, privateKey);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        keyPair.put(PUBLIC_KEY, publicKey);
        keyPair.put(PRIVATE_KEY, privateKey);
    }

    @Override
    public void createKeyPair(Context ctx, String alias, Integer userAuthenticationValidityDuration){
    }
}
