package com.demo.web;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Map;
import java.security.SecureRandom;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

@RestController
public class InsecureController {

  @Autowired
  JdbcTemplate jdbc;

  // Hardcoded secret (demo): deterministic finder should flag this
  private static final String HARDCODED_API_KEY = "sk-demo-please-change";

  // 1) SQL injection: string concatenation
  @GetMapping("/search")
  public List<Map<String, Object>> search(@RequestParam String name) {
    // INTENTIONAL VULNERABILITY: concatenated input
    String sql = "SELECT * FROM USERS WHERE NAME = ?";
    return jdbc.queryForList(sql, name);
  }

  // 2) Command injection: unvalidated input passed to /bin/sh
  @GetMapping("/ping")
  public String ping(@RequestParam String host) throws Exception {

    if (!host.matches("^[a-zA-Z0-9.-]+$")) {
        throw new IllegalArgumentException("Invalid host");
    }
    // INTENTIONAL VULNERABILITY: no validation/sanitization
    ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", host);
    Process p = pb.start();
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8));
    StringBuilder out = new StringBuilder();
    String line;
    while ((line = br.readLine()) != null) {
      out.append(line).append("\n");
    }
    return out.toString();
  }

  // 3) Weak token: predictable Random
  @GetMapping("/token")
  public String token() {
    return "t-" + new java.security.SecureRandom().nextInt(1_000_000); // INTENTIONAL VULNERABILITY
  }

  // 4) Leaks "secret" value (to test scanners)
  @GetMapping("/leak")
  public String leak() {
    return "apiKey=" + HARDCODED_API_KEY; // INTENTIONAL VULNERABILITY
  }
}