package com.example.controller;

import com.example.model.User;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

@Controller
@RequestMapping("/users")
public class UserController {

    private static final Logger logger = LogManager.getLogger(UserController.class);
    
    // VULNERABILITY: Hardcoded database credentials
    private static final String DB_URL = "jdbc:mysql://localhost:3306/vulnerable_db";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "password123";

    // VULNERABILITY: SQL Injection
    @GetMapping("/search")
    @ResponseBody
    public String searchUsers(@RequestParam String username) {
        StringBuilder result = new StringBuilder();
        Connection conn = null;
        Statement stmt = null;
        
        try {
            conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            stmt = conn.createStatement();
            
            // VULNERABILITY: Direct string concatenation in SQL query
            String sql = "SELECT * FROM users WHERE username LIKE '%" + username + "%'";
            ResultSet rs = stmt.executeQuery(sql);
            
            while (rs.next()) {
                result.append("User: ").append(rs.getString("username")).append("<br>");
            }
            
            rs.close();
        } catch (SQLException e) {
            logger.error("Database error: " + e.getMessage());
            return "Error: " + e.getMessage(); // VULNERABILITY: Error disclosure
        } finally {
            try {
                if (stmt != null) stmt.close();
                if (conn != null) conn.close();
            } catch (SQLException e) {
                logger.error("Error closing database resources: " + e.getMessage());
            }
        }
        
        return result.toString();
    }

    // VULNERABILITY: Cross-Site Scripting (XSS)
    @GetMapping("/profile")
    public String userProfile(@RequestParam String name, Model model) {
        // VULNERABILITY: Unsanitized user input passed to the view
        model.addAttribute("welcomeMessage", "Welcome, " + name + "!");
        return "profile";
    }

    // VULNERABILITY: Path Traversal
    @GetMapping("/download")
    @ResponseBody
    public void downloadFile(@RequestParam String filename, HttpServletResponse response) {
        try {
            // VULNERABILITY: Unsanitized path allows directory traversal
            File file = new File(filename);
            FileInputStream fis = new FileInputStream(file);
            
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment; filename=" + file.getName());
            
            OutputStream os = response.getOutputStream();
            byte[] buffer = new byte[4096];
            int bytesRead;
            
            while ((bytesRead = fis.read(buffer)) != -1) {
                os.write(buffer, 0, bytesRead);
            }
            
            fis.close();
            os.flush();
        } catch (IOException e) {
            logger.error("File error: " + e.getMessage());
        }
    }

    // VULNERABILITY: Command Injection
    @GetMapping("/ping")
    @ResponseBody
    public String pingHost(@RequestParam String host) {
        try {
            // VULNERABILITY: Unsanitized input passed to system command
            Process process = Runtime.getRuntime().exec("ping -c 4 " + host);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                output.append(line).append("<br>");
            }
            
            return output.toString();
        } catch (IOException e) {
            logger.error("Command execution error: " + e.getMessage());
            return "Error: " + e.getMessage();
        }
    }

    // VULNERABILITY: Insecure Direct Object Reference (IDOR)
    @GetMapping("/{userId}")
    @ResponseBody
    public String getUserDetails(@PathVariable int userId) {
        // VULNERABILITY: No authorization check
        Connection conn = null;
        PreparedStatement stmt = null;
        
        try {
            conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            String sql = "SELECT * FROM users WHERE id = ?";
            stmt = conn.prepareStatement(sql);
            stmt.setInt(1, userId);
            
            ResultSet rs = stmt.executeQuery();
            
            if (rs.next()) {
                return "User ID: " + rs.getInt("id") + "<br>" +
                       "Username: " + rs.getString("username") + "<br>" +
                       "Email: " + rs.getString("email") + "<br>";
            } else {
                return "User not found";
            }
        } catch (SQLException e) {
            logger.error("Database error: " + e.getMessage());
            return "Error: " + e.getMessage();
        } finally {
            try {
                if (stmt != null) stmt.close();
                if (conn != null) conn.close();
            } catch (SQLException e) {
                logger.error("Error closing database resources: " + e.getMessage());
            }
        }
    }

    // VULNERABILITY: Sensitive data in cookie
    @GetMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password, HttpServletResponse response) {
        if (authenticateUser(username, password)) {
            // VULNERABILITY: Sensitive data in cookie
            Cookie cookie = new Cookie("auth", username + ":" + password);
            cookie.setPath("/");
            response.addCookie(cookie);
            
            return "redirect:/users/dashboard";
        } else {
            return "redirect:/login?error=true";
        }
    }

    // VULNERABILITY: Insecure deserialization
    @PostMapping("/import")
    @ResponseBody
    public String importData(@RequestParam("data") String serializedData) {
        try {
            // VULNERABILITY: Insecure deserialization
            ByteArrayInputStream bais = new ByteArrayInputStream(serializedData.getBytes());
            ObjectInputStream ois = new ObjectInputStream(bais);
            Object importedObject = ois.readObject();
            ois.close();
            
            return "Data imported successfully: " + importedObject.toString();
        } catch (Exception e) {
            logger.error("Deserialization error: " + e.getMessage());
            return "Error: " + e.getMessage();
        }
    }

    // VULNERABILITY: Weak password validation
    @PostMapping("/register")
    @ResponseBody
    public String registerUser(@RequestParam String username, @RequestParam String password, @RequestParam String email) {
        // VULNERABILITY: No password strength validation
        
        Connection conn = null;
        PreparedStatement stmt = null;
        
        try {
            conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            String sql = "INSERT INTO users (username, password, email) VALUES (?, ?, ?)";
            stmt = conn.prepareStatement(sql);
            stmt.setString(1, username);
            stmt.setString(2, password); // VULNERABILITY: Password stored in plaintext
            stmt.setString(3, email);
            
            int rowsAffected = stmt.executeUpdate();
            
            if (rowsAffected > 0) {
                return "User registered successfully";
            } else {
                return "Registration failed";
            }
        } catch (SQLException e) {
            logger.error("Database error: " + e.getMessage());
            return "Error: " + e.getMessage();
        } finally {
            try {
                if (stmt != null) stmt.close();
                if (conn != null) conn.close();
            } catch (SQLException e) {
                logger.error("Error closing database resources: " + e.getMessage());
            }
        }
    }

    private boolean authenticateUser(String username, String password) {
        Connection conn = null;
        Statement stmt = null;
        
        try {
            conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            stmt = conn.createStatement();
            
            // VULNERABILITY: SQL Injection vulnerability
            String sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            ResultSet rs = stmt.executeQuery(sql);
            
            return rs.next(); // User exists and credentials match
        } catch (SQLException e) {
            logger.error("Authentication error: " + e.getMessage());
            return false;
        } finally {
            try {
                if (stmt != null) stmt.close();
                if (conn != null) conn.close();
            } catch (SQLException e) {
                logger.error("Error closing database resources: " + e.getMessage());
            }
        }
    }
} 