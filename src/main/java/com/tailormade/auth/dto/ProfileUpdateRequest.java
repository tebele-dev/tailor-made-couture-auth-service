package com.tailormade.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class ProfileUpdateRequest {
    @Email(message = "Please provide a valid email address")
    private String email;
    
    @NotBlank(message = "Current password is required for password change")
    private String currentPassword;
    
    private String newPassword;
}