package com.abhijith.hashing;

import java.util.*;

import static com.abhijith.hashing.GenerateHash.generateHash;


public class PasswordHashing {

    public boolean authenticate() {  //calls captcha which prompts random 4 digit to enter
        
        HashMap<String, String> map = new HashMap<String, String>();
        boolean bool = false;
        PasswordHashing passwordHashing = new PasswordHashing();
        Captcha cap = new Captcha();

        map = passwordHashing.signup("abhijith", "password");
        String captch = cap.captch();
        System.out.println("please enter captcha");
        Scanner scanner = new Scanner(System.in);
        String input = scanner.nextLine();
        while (!input.equals(captch)) {
            System.out.println("enter correct captcha ");
            input = scanner.nextLine();
        }
        if ((passwordHashing.login("abhijith", "password", map))) {
            System.out.println("user login successfull.");
            return true;

        }
        // login should fail because of wrong password.
        if (passwordHashing.login("abhijth", "adfaddf", map)) {
            System.out.println("User login successfull.");
            return true;

        } else {
            System.out.println("user login failed.");
            return false;

        }

    }

    public HashMap<String, String> signup(String username, String password) {    //stores username and hashed password
        ReadingSaltFromText readingSaltFromText = new ReadingSaltFromText();
        HashMap<String, String> map = new HashMap<String, String>();
        String SALT = readingSaltFromText.readFile();
        String saltedPassword = SALT + password;
        String hashedPassword = generateHash(saltedPassword);                      //generates hash for password
        System.out.println(hashedPassword);
        map.put(username, hashedPassword);
        return map;
    }

    public Boolean login(String username, String password, HashMap<String, String> map) {   //checks user name and password against stored hashed password
        ReadingSaltFromText readingSaltFromText = new ReadingSaltFromText();
        String SALT = readingSaltFromText.readFile();
        boolean isAuthenticated;
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