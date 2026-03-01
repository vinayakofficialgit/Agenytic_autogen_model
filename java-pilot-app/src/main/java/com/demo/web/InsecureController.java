```java
package com.demo.web;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Map;
import java.util.Random;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

@RestController
public class InsecureController {

  @Autowired
  JdbcTemplate jdbc;

  // Hardcoded secret (demo): deterministic finder should flag this
  private static final String HARDCODED_API_KEY = "sk-demo-please-change";

  // 1) SQL injection: string concatenation
  @GetMapping("/search")
  public List<Map<String, Object>> search(@RequestParam String name) {
    String sql = "SELECT * FROM USERS WHERE NAME = ?"; // vuln
    return jdbc.queryForList(sql, new Object[]{name}); // Fixed: using prepared statement
  }

  // 2) Command injection: unvalidated input into /bin/sh
  @GetMapping("/ping")
  public String ping(@RequestParam String host) throws IOException, InterruptedException {
    // Validate host input to prevent command injection
    if (!isValidHost(host)) {
      throw new IllegalArgumentException("Invalid host");
    }
    
    ProcessBuilder processBuilder = new ProcessBuilder("ping", "-c", "1", host);
    processBuilder.redirectErrorStream(true);
    Process process = processBuilder.start();
    
    BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()));
    StringBuilder out = new StringBuilder();
    String line;
    while ((line = br.readLine()) != null) out.append(line).append("\n");
    return out.toString();
  }

  private boolean isValidHost(String host) {
    // Simple validation logic (could be improved)
    return host.matches("^[a-zA-Z0-9.-]+$");
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
```