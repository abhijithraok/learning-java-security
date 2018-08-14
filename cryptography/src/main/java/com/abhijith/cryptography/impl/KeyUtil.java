package com.abhijith.cryptography.impl;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

public class KeyUtil {
    public static Key generateSymmetricKey(String algorithm, int keySize, boolean bouncyProvider) {
        KeyGenerator keyGenerator = null;
        try {
            Provider provider = null;
            if (bouncyProvider) {
                provider = new BouncyCastleProvider();
                Security.addProvider(provider);
                keyGenerator = KeyGenerator.getInstance(algorithm, provider);
            } else {
                keyGenerator = keyGenerator.getInstance(algorithm);
            }

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();

        }
        keyGenerator.init(keySize, new SecureRandom());
        Key symmetrickKey = keyGenerator.generateKey();
        return symmetrickKey;
    }


    public static KeyPair generateAsymmetricKey(String algorithm, int keySize, boolean bouncyProvider) {

        KeyPairGenerator keyPairGenerator = null;
        try {
            Provider provider = null;
            if (bouncyProvider) {
                provider = new BouncyCastleProvider();
                Security.addProvider(provider);
                keyPairGenerator = KeyPairGenerator.getInstance(algorithm, provider);
            } else {
                keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
            }

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();

        }
        keyPairGenerator.initialize(keySize,new SecureRandom());
        KeyPair symmetrickKey = keyPairGenerator.generateKeyPair();
        return symmetrickKey;
    }

    public static void main(String [] args ){
        System.out.println(generateSymmetricKey("AESWithCTSAndPKCS5Padding",20,false));
    }

}

