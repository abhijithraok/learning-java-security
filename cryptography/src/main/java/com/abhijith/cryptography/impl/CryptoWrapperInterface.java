package com.abhijith.cryptography.impl;

public interface CryptoWrapperInterface {
    byte[] encrypt(final String input, final String password, final byte[] iv, final Algorithm algorithm);
    byte[] decrypt(final byte[] encryptedContent, final String password, final byte[] iv, final Algorithm algorithm) ;
    String sha1(String content) ;
    String md5(String content);
    String digest(String content, Algorithm algorithm);
}
