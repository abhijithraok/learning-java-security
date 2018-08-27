package com.abhijith.cryptography.impl;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

import static com.abhijith.cryptography.util.CryptographyConstant.DEFAULT_KEY_SIZE;


public class KeyUtil {
    /**
     * @param algorithm      used in key generation
     * @param keySize        : lenght of key
     * @param bouncyProvider
     * @return
     */
    public static Key generateSymmetricKey(Algorithm algorithm, int keySize, boolean bouncyProvider) {
        KeyGenerator keyGenerator = null;
        try {
            Provider provider = null;
            if (bouncyProvider) {
                provider = new BouncyCastleProvider();
                Security.addProvider(provider);
                keyGenerator = KeyGenerator.getInstance(algorithm.toString(), provider);
            } else {
                keyGenerator = keyGenerator.getInstance(algorithm.toString());
            }

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();

        }
        switch (algorithm) {
            case DES:
                keySize = 56;
                break;

            case AES:
                keySize =256;
                break;
        }

        keyGenerator.init(keySize, new SecureRandom());
        Key symmetrickKey = keyGenerator.generateKey();
        return symmetrickKey;
    }

    /**
     * @param algorithm
     * @param keySize
     * @param bouncyProvider
     * @return
     */
    public static KeyPair generateAsymmetricKey(Algorithm algorithm, int keySize, boolean bouncyProvider) {

        KeyPairGenerator keyPairGenerator = null;
        try {
            Provider provider = null;
            if (bouncyProvider) {
                provider = new BouncyCastleProvider();
                Security.addProvider(provider);
                keyPairGenerator = KeyPairGenerator.getInstance(algorithm.toString(), provider);
            } else {
                keyPairGenerator = KeyPairGenerator.getInstance(algorithm.toString());
            }

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();

        }
        keyPairGenerator.initialize(keySize, new SecureRandom());
        KeyPair symmetrickKey = keyPairGenerator.generateKeyPair();
        return symmetrickKey;
    }


}

