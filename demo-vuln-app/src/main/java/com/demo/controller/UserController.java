package com.demo.controller;

import java.sql.*;
import java.io.PrintWriter;
import javax.servlet.*;
import javax.servlet.http.*;

public class UserController extends HttpServlet {

    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {

        String id = req.getParameter("id");

        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test");
        Statement stmt = conn.createStatement();

        // ⭐ SQL Injection
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id=" + id);

        // ⭐ XSS
        PrintWriter out = res.getWriter();
        out.println("<h1>User: " + req.getParameter("name") + "</h1>");
    }
}