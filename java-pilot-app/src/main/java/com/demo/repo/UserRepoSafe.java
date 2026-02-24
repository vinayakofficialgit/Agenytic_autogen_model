package com.demo.repo;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Map;

@Repository
public class UserRepoSafe {

  @Autowired
  JdbcTemplate jdbc;

  // SAFE pattern the AI should replicate:
  public List<Map<String,Object>> findByName(String name) {
    String sql = "SELECT * FROM USERS WHERE NAME = ?";
    return jdbc.queryForList(sql, name);
  }
}
