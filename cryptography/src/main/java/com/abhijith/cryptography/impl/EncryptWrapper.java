package com.abhijith.cryptography.impl;
import static com.abhijith.cryptography.util.CryptographyConstant.*;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptWrapper implements CryptoWrapperInterface {
private  static Logger logger = Logger.getLogger(EncryptWrapper.class.getName());

@Override
    public byte [] encrypt(final String input, final String password, final byte[] iv, final Algorithm algorithm) {
        try {
            final SecretKeySpec keySpec = generateKey(password, algorithm);
            Cipher cipher = Cipher.getInstance(algorithm.toString());
            if (iv == null) {
                cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            } else {
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            }
            logger.info("Default cipher algorithm initialized!!");
            byte[] result = cipher.doFinal(input.getBytes(CHARSET));
            return result;
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | UnsupportedEncodingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    return null;
    }



    /**
     * decrypt content
     * @param password password
     * @return decrypted content
     */


   @Override
    public byte[] decrypt(final byte[] encryptedContent, final String password, final byte[] iv, final Algorithm algorithm) {
        try {
            final SecretKeySpec keySpec = generateKey(password, algorithm);
            Cipher cipher = Cipher.getInstance(algorithm.toString());
            if (iv == null) {
                cipher.init(Cipher.DECRYPT_MODE, keySpec);
            } else {
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            }
            byte[] result = cipher.doFinal(encryptedContent);
            return result;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeyException  | BadPaddingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }

  /*  private  SecretKeySpec generateKey(final String password, final Algorithm algorithm) {
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
            return new SecretKeySpec(encodedFormat, algorithm.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } //catch (NoSuchProviderException e) {
         //   e.printStackTrace();
      //  }
        return null;
    }
    */

@Override
    public  String sha1(String content) {
        return digest(content, Algorithm.SHA1);
    }
@Override
    public  String md5(String content) {
        return digest(content, Algorithm.MD5);
    }
@Override
    public  String digest(String content, Algorithm algorithm) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm.toString());
            messageDigest.update(content.getBytes(CHARSET));
            byte[] result = messageDigest.digest();
            return byte2Hex(result);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    return null;
    }

    private  String byte2Hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b: bytes) {
            String hex = Integer.toHexString(b & 0xFF);
            if (hex.length() == 1) {
                hex = "0" + hex;   // one byte to double-digit hex
            }
            sb.append(hex);
        }
        return sb.toString();
    }


    public static void main(String[] args) {
        String content = "Test contsdfaafa";
        String password = "password!@#";
        System.out.println("content:" + content + "\n");
EncryptWrapper encryptWrapper = new EncryptWrapper();
        byte[] encrypted = encryptWrapper.encrypt(content, password,null,Algorithm.AES);
        System.out.println("AES encrypt:" + Arrays.toString(encrypted));
        System.out.println("AES decrypt:" + Arrays.toString(encryptWrapper.decrypt(encrypted, password, null, Algorithm.AES)) + "\n");

        encrypted = encryptWrapper.encrypt(content, password,null, Algorithm.DES);
        System.out.println("DES encrypt:" + Arrays.toString(encrypted));
        System.out.println("DES decrypt:" + Arrays.toString(encryptWrapper.decrypt(encrypted, password, null, Algorithm.DES)) + "\n");

        System.out.println("md5 hash:" + encryptWrapper.md5(content));
        System.out.println("sha256 hash:" + encryptWrapper.digest(content, Algorithm.SHA256));

    }
}


