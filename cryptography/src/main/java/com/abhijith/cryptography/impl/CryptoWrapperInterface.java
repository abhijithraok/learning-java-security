package com.abhijith.cryptography.impl;

public interface CryptoWrapperInterface {

    String encrypt(final String content, final String password, final byte[] iv, final Algorithm algorithm, final Algorithm cipherAlgorithm);

    String decrypt(final String encryptedContent, final String password, final byte[] iv, final Algorithm algorithm, final Algorithm cipherAlgorith);

    String digest(String content, Algorithm algorithm);
}
