package com.demo.service;

import java.io.File;
import java.nio.file.Files;

public class FileService {

    public String readFile(String filename) throws Exception {
        File f = new File("/data/" + filename); // path traversal
        return Files.readString(f.toPath());
    }
}