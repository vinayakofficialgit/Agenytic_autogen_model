package com.demo.util;

import java.io.*;
import java.net.URL;

public class InsecureUtil {

    public static String exec(String cmd) throws Exception {
        Process p = Runtime.getRuntime().exec(cmd);
        return "executed";
    }

    public static String readFile(String name) throws Exception {
        File f = new File("/tmp/" + name);
        return new String(java.nio.file.Files.readAllBytes(f.toPath()));
    }

    public static String fetch(String u) throws Exception {
        URL url = new URL(u);
        return url.toString();
    }
}