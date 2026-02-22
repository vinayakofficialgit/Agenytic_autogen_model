package com.demo.service;

import java.sql.*;

public class DbService {

    public String getUser(String id) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test","root","root");
        Statement stmt = conn.createStatement();

        ResultSet rs = stmt.executeQuery("SELECT name FROM users WHERE id=" + id);

        if (rs.next()) return rs.getString(1);
        return "not found";
    }
}