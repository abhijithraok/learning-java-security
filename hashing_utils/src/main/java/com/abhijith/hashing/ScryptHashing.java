package com.abhijith.hashing;

import com.lambdaworks.crypto.SCryptUtil;

import java.security.NoSuchAlgorithmException;

public class ScryptHashing {
    public static String getScrypt(String input) throws NoSuchAlgorithmException {
        String generatedSecuredPassword = SCryptUtil.scrypt(input, 16, 16, 16);
        boolean matched = SCryptUtil.check("password", generatedSecuredPassword);
      //  System.out.println(matched);

        matched = SCryptUtil.check("passwordno", generatedSecuredPassword);
        System.out.println(matched);
        return generatedSecuredPassword;
    }
}
