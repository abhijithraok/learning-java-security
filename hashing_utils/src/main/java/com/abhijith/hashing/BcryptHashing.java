package com.abhijith.hashing;

import org.mindrot.jbcrypt.BCrypt;

import java.security.NoSuchAlgorithmException;
import java.security.*;

public class BcryptHashing {
    public static String getBcrypt(String input) throws NoSuchAlgorithmException {
        String generatedSecuredPassword = BCrypt.hashpw(input, BCrypt.gensalt(12));
        System.out.println(generatedSecuredPassword);
        return generatedSecuredPassword;
    }
}