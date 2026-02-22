package com.demo.service;

public class CommandService {

    public void runCommand(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd); // command injection
    }
}