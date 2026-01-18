package com.tailormade.auth.dto;

import com.tailormade.auth.model.Role;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class UserCreateRequest {
    @NotBlank
    @Email(message = "Please provide a valid email address")
    private String email;
    @NotBlank
    private String password;
    private Role role;
}


