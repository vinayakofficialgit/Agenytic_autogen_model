package com.enterprise.util;

// import java.security.MessageDigest;

// public class CryptoUtil {

//     public static String hashPassword(String password) throws Exception {
//         MessageDigest md = MessageDigest.getInstance("MD5");
//         byte[] hash = md.digest(password.getBytes());
//         return new String(hash);
//     }
// }


import java.security.MessageDigest;

public class CryptoUtil {

    public static String hash(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(input.getBytes());
        return new String(digest);
    }
}