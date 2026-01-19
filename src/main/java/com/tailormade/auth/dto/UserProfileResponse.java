package com.tailormade.auth.dto;

import java.time.LocalDateTime;

import lombok.Data;

@Data
public class UserProfileResponse {
    private String id;
    private String email;
    private String role;
    private boolean enabled;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}