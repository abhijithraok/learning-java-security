package com.abhijith.hashing;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;


public class PasswordHashing {
    private static final String SALT = "abhijith";
    private Map<String, String> map = new HashMap<String, String>();

    public static void main(String args[]) {
        PasswordHashing passwordHashing = new PasswordHashing();

        passwordHashing.authenticate();


    }

    private static String generateHash(String input) {
        StringBuilder hash = new StringBuilder();

        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            byte[] hashedBytes = sha.digest(input.getBytes());
            char[] digits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                    'a', 'b', 'c', 'd', 'e', 'f'};
            for(byte temp: hashedBytes){
                byte b = temp;
                hash.append(digits[(b & 0xf0) >> 4]);
                hash.append(digits[b & 0x0f]);
            }
        } catch (NoSuchAlgorithmException e) {

        }

        return hash.toString();
    }

    private void authenticate() {
        PasswordHashing passwordHashing = new PasswordHashing();
        passwordHashing.signup("abhijith", "password");
        String captch = captch();
        System.out.println("please enter captcha");
        Scanner scanner = new Scanner(System.in);
        String input = scanner.nextLine();
        while (!input.equals(captch)) {
            System.out.println("enter correct captcha ");
            input = scanner.nextLine();
        }
        if (passwordHashing.login("abhijith", "password"))
            System.out.println("user login successfull.");

        // login should fail because of wrong password.
        if (passwordHashing.login("abhijth", "adfaddf"))
            System.out.println("User login successfull.");
        else
            System.out.println("user login failed.");


    }

    private String captch() {
        String randomChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        StringBuilder sb = new StringBuilder();
        Random rnd = new Random();
        while (sb.length() < 5) {
            int index = (int) (rnd.nextFloat() * randomChars.length());
            sb.append(randomChars.charAt(index));

        }
        String randomDigit = sb.toString();
        System.out.println(randomDigit);
        return randomDigit;
    }


  // private  String captch(){
       //    File file = new File("randomString.txt");




   //    return "a";
 //  }
    private void signup(String username, String password) {
        String saltedPassword = SALT + password;
        String hashedPassword = generateHash(saltedPassword);
        map.put(username, hashedPassword);

    }

    private Boolean login(String username, String password) {
        boolean isAuthenticated ;
        String saltedPassword = SALT + password;
        String hashedPassword = generateHash(saltedPassword);

        String storedPasswordHash = map.get(username);
        if (hashedPassword.equals(storedPasswordHash)) {
            isAuthenticated = true;
        } else {
            isAuthenticated = false;
        }
        return isAuthenticated;
    }

}