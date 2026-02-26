package com.demo.web;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Map;
import java.util.Random;
import java.io.BufferedReader;
import java.io.InputStreamReader;

@RestController
public class InsecureController {

  @Autowired
  JdbcTemplate jdbc;

  // Hardcoded secret (demo): deterministic finder should flag this
  private static final String HARDCODED_API_KEY = "sk-demo-please-change";

  // 1) SQL injection: string concatenation
  @GetMapping("/search")
  public List<Map<String, Object>> search(@RequestParam String name) {
    String sql = "SELECT * FROM USERS WHERE NAME = '" + name + "'"; // vuln
    return jdbc.queryForList(sql);
  }

  // 2) Command injection: unvalidated input into /bin/sh
  @GetMapping("/ping")
  public String ping(@RequestParam String host) throws Exception {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh","-c","ping -c 1 " + host}); // vuln
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    StringBuilder out = new StringBuilder();
    String line;
    while ((line = br.readLine()) != null) out.append(line).append("");
    return out.toString();
  }

  // 3) Weak token: predictable Random
  @GetMapping("/token")
  public String token() {
    return "t-" + new Random().nextInt(1_000_000); // vuln
  }

  // 4) Leaks “secret” value (to test scanners)
  @GetMapping("/leak")
  public String leak() {
    return "apiKey=" + HARDCODED_API_KEY; // vuln
  }
}