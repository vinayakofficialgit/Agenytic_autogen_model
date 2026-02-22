package com.demo.controller;

import com.demo.service.DbService;
import com.demo.util.InsecureUtil;
import org.springframework.web.bind.annotation.*;

@RestController
public class VulnController {

    private final DbService dbService = new DbService();

    // SQL injection
    @GetMapping("/user")
    public String getUser(@RequestParam String id) throws Exception {
        return dbService.getUser(id);
    }

    // XSS
    @GetMapping("/hello")
    public String hello(@RequestParam String name) {
        return "<h1>Hello " + name + "</h1>";
    }

    // command injection
    @GetMapping("/exec")
    public String exec(@RequestParam String cmd) throws Exception {
        return InsecureUtil.exec(cmd);
    }

    // path traversal
    @GetMapping("/file")
    public String read(@RequestParam String name) throws Exception {
        return InsecureUtil.readFile(name);
    }

    // SSRF
    @GetMapping("/fetch")
    public String fetch(@RequestParam String url) throws Exception {
        return InsecureUtil.fetch(url);
    }
}