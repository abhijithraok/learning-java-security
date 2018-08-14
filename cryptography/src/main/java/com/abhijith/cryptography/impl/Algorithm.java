package com.abhijith.cryptography.impl;

public enum Algorithm {
    //encryption algorithm
    AES("AES/ECB/PKCS1Padding"), DES("DES/ECB/PKCS1Padding"), RSA("RSA/ECB/PKCS1Padding"),

    // message digest algorithm
    MD2("MD2"),
    MD5("MD5"),
    SHA1("SHA-1"),
    SHA256("SHA-256"),
    SHA384("SHA-384"),
    SHA512("SHA-512");

    private final String text;

    Algorithm(final String text) {
        this.text = text;
    }

    @Override
    public String toString() {
        return text;
    }
}

