package com.tailormade.auth.dto;

import lombok.Data;

@Data
public class AuthResponse {
    private String token;
    private String refreshToken;
    private String type = "Bearer";
    private String email;
    private String role;

    public AuthResponse() {
    }

    public AuthResponse(String token, String refreshToken, String type, String email, String role) {
        this.token = token;
        this.refreshToken = refreshToken;
        this.type = type;
        this.email = email;
        this.role = role;
    }

    public String getAccessToken() {
        return token;
    }

    public String getTokenType() {
        return type;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
