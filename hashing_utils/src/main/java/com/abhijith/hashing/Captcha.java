package com.abhijith.hashing;

import java.io.InputStream;
import java.util.Random;
import java.util.Scanner;

class Captcha {

    protected String captch() {  //generates random 4 alphanumeric from randomChar strings


        String randomChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

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
}