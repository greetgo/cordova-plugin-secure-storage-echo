package com.crypho.plugins;

import android.os.Build;

import java.util.Hashtable;

public class RSAFactory {
    public static AbstractRSA getRSA(boolean isCustomRSA) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return new RSALegacy();
        }
        try {
        if(isCustomRSA){
            return new RSAOAEP();
        }else{
        return new RSA();
        }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
