package com.abhijith.cryptography.impl;

import static com.abhijith.cryptography.util.CryptographyConstant.*;

import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author abhijith
 * @date 8/13/2018
 * @description common encrypt and decrypt
 */
public class EncryptWrapperImpl implements CryptoWrapperInterface {
    private static Logger logger = Logger.getLogger(EncryptWrapperImpl.class.getName());

    /**
     *
     * @param bytes
     * @return string value of byte array
     */
    private static String byte2Hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(b & 0xFF);
            if (hex.length() == 1) {
                hex = "0" + hex;   // one byte to double-digit hex
            }
            sb.append(hex);
        }
        return sb.toString();
    }

    /**
     *
     * @param hex
     * @return byte array
     */
    private static byte[] hex2byte(String hex) {
        if (hex == null || hex.length() < 1) {
            return null;
        }
        int len = hex.length() / 2;
        byte[] bytes = new byte[len];
        for (int i = 0; i < len; i++) {
            int high = Integer.parseInt(hex.substring(i * 2, i * 2 + 1), 16);
            int low = Integer.parseInt(hex.substring(i * 2 + 1, i * 2 + 2), 16);
            bytes[i] = (byte) (high * 16 + low);
        }
        return bytes;
    }

    /**
     * encrypt content
     * @param content
     * @param password
     * @param iv initialization vector
     * @param algorithm AES,DES for Secret key
     * @param cipherAlgorithm used in cipher mode
     * @return encrypted content
     */
    @Override
    public String encrypt(final String content, final String password, final byte[] iv, final Algorithm algorithm, final Algorithm cipherAlgorithm) {

        try {

            final SecretKeySpec keySpec = generateKey(password, algorithm);
            Cipher cipher = Cipher.getInstance(cipherAlgorithm.toString());
            if (iv == null) {
                cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            } else {
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            }
            logger.info("Default cipher algorithm initialized!!");
            byte[] result = cipher.doFinal(content.getBytes(CHARSET));
            return byte2Hex(result);
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | UnsupportedEncodingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     *
     * @param encryptedContent
     * @param password
     * @param iv initialization vector
     * @param algorithm : AES,DES
     * @param cipherAlgorithm
     * @return decypted content
     */

    @Override
    public String decrypt(final String encryptedContent, final String password, final byte[] iv, final Algorithm algorithm, final Algorithm cipherAlgorithm) {

        try {

            final SecretKeySpec keySpec = generateKey(password, algorithm);
            Cipher cipher = Cipher.getInstance(cipherAlgorithm.toString());
            if (iv == null) {
                cipher.init(Cipher.DECRYPT_MODE, keySpec);
            } else {
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            }
            byte[] result = cipher.doFinal(hex2byte(encryptedContent));
            logger.info("decrypted!");
            return new String(result, CHARSET);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeyException | BadPaddingException | UnsupportedEncodingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     *
     * @param password
     * @param algorithm
     * @return
     */
    private SecretKeySpec generateKey(final String password, final Algorithm algorithm) {
        try {
            final KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm.toString());
            SecureRandom secureRandom;
            secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(password.getBytes());
            int keySize = DEFAULT_KEY_SIZE;
            switch (algorithm) {
                case DES:
                    keySize = 56;
                    break;
            }
            keyGenerator.init(keySize, secureRandom);
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] encodedFormat = secretKey.getEncoded();
            logger.info("generate secret key spec!");
            return new SecretKeySpec(encodedFormat, algorithm.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } //catch (NoSuchProviderException e) {
        //   e.printStackTrace();
        //  }
        return null;
    }

    /**
     *
     * @param content get hash value using this
     * @param algorithm of hash
     * @return hash value
     */

    @Override
    public String digest(String content, Algorithm algorithm) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm.toString());
            messageDigest.update(content.getBytes(CHARSET));
            byte[] result = messageDigest.digest();
            logger.info("message digest ");
            return byte2Hex(result);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

}


