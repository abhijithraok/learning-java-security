package com.abhijith.cryptography.impl;
import static com.abhijith.cryptography.util.CryptographyConstant.*;
import java.io.UnsupportedEncodingException;
import java.security.*;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
public class EncryptWrapper implements CryptoWrapperInterface {
private  static Logger logger = Logger.getLogger(EncryptWrapper.class.getName());

@Override
    public String encrypt(final String content, final String password, final byte[] iv, final Algorithm algorithm,final Algorithm cipherAlgorithm) {

        try {
          //  Provider provider = new BouncyCastleProvider();
         //   Security.addProvider(provider);
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



   @Override
    public String decrypt(final String encryptedContent, final String password, final byte[] iv, final Algorithm algorithm,final Algorithm cipherAlgorithm){

        try {
         //   Provider provider = new BouncyCastleProvider();
         //   Security.addProvider(provider);
            final SecretKeySpec keySpec = generateKey(password, algorithm);
            Cipher cipher = Cipher.getInstance(cipherAlgorithm.toString());
            if (iv == null) {
                cipher.init(Cipher.DECRYPT_MODE, keySpec);
            } else {
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            }
            byte[] result = cipher.doFinal(hex2byte(encryptedContent));
            return new String(result,CHARSET);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeyException  | BadPaddingException |UnsupportedEncodingException| InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }

    private  SecretKeySpec generateKey(final String password, final Algorithm algorithm) {
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

    private static String byte2Hex(byte[] bytes) {
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

    public static void main(String[] args) {
        String content = "Test user input ";
        String password = "mypassword";
        System.out.println("content:" + content + "\n");
EncryptWrapper encryptWrapper = new EncryptWrapper();
        String encrypted = encryptWrapper.encrypt(content, password,null,Algorithm.AES,Algorithm.AES_CIPHER);
        System.out.println("AES encrypt:" + (encrypted));
        System.out.println("AES decrypt:" + (encryptWrapper.decrypt(encrypted, password, null, Algorithm.AES,Algorithm.AES_CIPHER)) + "\n");

        encrypted = encryptWrapper.encrypt(content, password,null, Algorithm.DES,Algorithm.DES_CIPHER);
        System.out.println("DES encrypt:" + (encrypted));
        System.out.println("DES decrypt:" + (encryptWrapper.decrypt(encrypted, password, null, Algorithm.DES,Algorithm.DES_CIPHER)) + "\n");

        System.out.println("md5 hash:" + encryptWrapper.md5(content));
        System.out.println("sha256 hash:" + encryptWrapper.digest(content, Algorithm.SHA256));

    }
}


