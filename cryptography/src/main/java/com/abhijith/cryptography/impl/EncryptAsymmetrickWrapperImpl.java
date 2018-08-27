package com.abhijith.cryptography.impl;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.logging.Logger;

import static com.abhijith.cryptography.encode.ByteToHex.byte2Hex;
import static com.abhijith.cryptography.encode.HexToByte.hex2byte;
import static com.abhijith.cryptography.util.CryptographyConstant.CHARSET;
import static com.abhijith.cryptography.util.CryptographyConstant.DEFAULT_KEY_SIZE;

public class EncryptAsymmetrickWrapperImpl implements CryptoWrapperInterface {
    private static Logger logger = Logger.getLogger(EncryptSymmetrickWrapperImpl.class.getName());
    private static KeyPair asymmetrickKey = null;


    /**
     * encrypt content
     *
     * @param content
     * @param password
     * @param iv              initialization vector
     * @param algorithm       AES,DES for Secret key
     * @param cipherAlgorithm used in cipher mode
     * @return encrypted content
     */
    @Override
    public String encrypt(final String content, final String password, final byte[] iv, final Algorithm algorithm, final Algorithm cipherAlgorithm) {
        KeyUtil keyUtil = new KeyUtil();
        try {


            asymmetrickKey = KeyUtil.generateAsymmetricKey(algorithm, DEFAULT_KEY_SIZE, false);

            Cipher cipher = Cipher.getInstance(cipherAlgorithm.toString());
            if (iv == null) {
                cipher.init(Cipher.ENCRYPT_MODE, asymmetrickKey.getPublic());
            } else {
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, asymmetrickKey.getPublic(), ivSpec);
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
     * @param encryptedContent
     * @param password
     * @param iv               initialization vector
     * @param algorithm        : AES,DES
     * @param cipherAlgorithm
     * @return decypted content
     */

    @Override
    public String decrypt(final String encryptedContent, final String password, final byte[] iv, final Algorithm algorithm, final Algorithm cipherAlgorithm) {

        try {

            //  final SecretKeySpec keySpec = generateKey(password, algorithm);
            Cipher cipher = Cipher.getInstance(cipherAlgorithm.toString());
            if (iv == null) {
                cipher.init(Cipher.DECRYPT_MODE, asymmetrickKey.getPrivate());
            } else {
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, asymmetrickKey.getPrivate(), ivSpec);
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
     * @param content   get hash value using this
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







