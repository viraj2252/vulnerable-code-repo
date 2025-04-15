package com.example.model;

import java.io.Serializable;

public class User implements Serializable {
    // VULNERABILITY: Serializable class without serialVersionUID
    
    private int id;
    private String username;
    private String password; // VULNERABILITY: Storing password in plaintext
    private String email;
    private boolean isAdmin;
    
    // Default constructor required for serialization
    public User() {
    }
    
    public User(int id, String username, String password, String email, boolean isAdmin) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.email = email;
        this.isAdmin = isAdmin;
    }
    
    public int getId() {
        return id;
    }
    
    public void setId(int id) {
        this.id = id;
    }
    
    public String getUsername() {
        return username;
    }
    
    public void setUsername(String username) {
        this.username = username;
    }
    
    public String getPassword() {
        return password; // VULNERABILITY: Directly exposing the password
    }
    
    public void setPassword(String password) {
        this.password = password; // VULNERABILITY: No password hashing
    }
    
    public String getEmail() {
        return email;
    }
    
    public void setEmail(String email) {
        this.email = email;
    }
    
    public boolean isAdmin() {
        return isAdmin;
    }
    
    public void setAdmin(boolean isAdmin) {
        this.isAdmin = isAdmin;
    }
    
    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' + // VULNERABILITY: Including password in toString
                ", email='" + email + '\'' +
                ", isAdmin=" + isAdmin +
                '}';
    }
} 