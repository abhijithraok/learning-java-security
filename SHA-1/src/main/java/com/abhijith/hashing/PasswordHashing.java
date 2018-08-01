package com.abhijith.hashing;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
public class PasswordHashing {
  private   Map<String, String> map = new HashMap<String, String>();
    public static final String SALT = "abhijith";

    public static void main(String args[]) {
        PasswordHashing passwordHashing = new PasswordHashing();
        passwordHashing.signup("abhijith", "password");

        // login should succeed.
        if (passwordHashing.login("abhijith", "password"))
            System.out.println("user login successfull.");

        // login should fail because of wrong password.
      if (passwordHashing.login("abhijth", "adfaddf"))
            System.out.println("User login successfull.");
        else
            System.out.println("user login failed.");
    }

    public void signup(String username, String password) {
        String saltedPassword = SALT + password;
        String hashedPassword = generateHash(saltedPassword);
        map.put(username, hashedPassword);

    }

    public Boolean login(String username, String password) {
        Boolean isAuthenticated = false;
        String saltedPassword = SALT + password;
        String hashedPassword = generateHash(saltedPassword);

        String storedPasswordHash = map.get(username);
        if(hashedPassword.equals(storedPasswordHash)){
            isAuthenticated = true;
        }else{
            isAuthenticated = false;
        }
        return isAuthenticated;
    }

    public static String generateHash(String input) {
        StringBuilder hash = new StringBuilder();

        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            byte[] hashedBytes = sha.digest(input.getBytes());
            char[] digits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                    'a', 'b', 'c', 'd', 'e', 'f' };
            for (int idx = 0; idx < hashedBytes.length; ++idx) {
                byte b = hashedBytes[idx];
                hash.append(digits[(b & 0xf0) >> 4]);
                hash.append(digits[b & 0x0f]);
            }
        } catch (NoSuchAlgorithmException e) {

        }

        return hash.toString();
    }

}