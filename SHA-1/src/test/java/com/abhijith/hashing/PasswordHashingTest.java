package com.abhijith.hashing;

import org.junit.Test;

import java.util.HashMap;

import static org.junit.Assert.*;

public class PasswordHashingTest {


    @Test
    public void login() {
        PasswordHashing passwordHashing = new PasswordHashing();
        HashMap<String, String> map = new HashMap<String, String>();
        map = passwordHashing.signup("abhijith", "password");
        assertEquals(true, passwordHashing.login("abhijith", "password", map));
        assertEquals(true, passwordHashing.login("abhijith", "passwo", map));
        assertEquals(false, passwordHashing.login("abhiji", "password", map));
    }

}