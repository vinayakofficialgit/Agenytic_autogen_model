package com.enterprise.controller;

import org.springframework.web.bind.annotation.*;

import java.sql.*;
import java.io.*;

@RestController
@RequestMapping("/api")
public class UserController {

    private static final String SECRET = "hardcodedSecret123";

    @GetMapping("/user")
    public String getUser(@RequestParam String id) throws Exception {

        Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/test",
                "root",
                "root123"
        );

        Statement stmt = conn.createStatement();

        ResultSet rs = stmt.executeQuery(
                "SELECT * FROM users WHERE id=" + id
        );

        return "User fetched";
    }

    @GetMapping("/ping")
    public String ping(@RequestParam String host) throws Exception {
        String cmd = "ping -c 1 " + host;
        //Runtime.getRuntime().exec(cmd);
        Runtime.getRuntime().exec("ls " + host);
        return "Pinged";
    }

    @GetMapping("/welcome")
    public String welcome(@RequestParam String name) {
        return "<h1>Welcome " + name + "</h1>";
    }

    // @GetMapping("")
    // public String home() {
    //     return "Enterprise DevSecOps App Running";
    // }

    @PostMapping("/deserialize")
    public String deserialize(@RequestBody byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(data)
        );
        Object obj = ois.readObject();
        return obj.toString();
    }
}