package com.abhijith.hashing;

import java.io.File;
import java.io.InputStream;
import java.util.Scanner;

public class ReadingSaltFromText {  //reading salt from text
    public String readFile() {
        String salt = "";
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        InputStream inputStream = classLoader.getResourceAsStream("salt.txt");
        Scanner scanner = new Scanner(inputStream);
        salt = scanner.nextLine();
        return salt;
    }
}
