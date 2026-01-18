package com.tailormade.auth.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tailormade.auth.dto.AuthRequest;
import com.tailormade.auth.dto.UserCreateRequest;
import com.tailormade.auth.model.Role;
import com.tailormade.auth.model.User;
import com.tailormade.auth.service.UserService;
import com.tailormade.auth.util.JwtUtil;
import com.tailormade.auth.util.LoginAttemptTracker;
import com.tailormade.auth.util.TokenBlacklist;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private UserService userService;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private TokenBlacklist tokenBlacklist;

    @Mock
    private LoginAttemptTracker loginAttemptTracker;

    @InjectMocks
    private AuthController authController;

    private MockMvc mockMvc;

    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(authController).build();
        objectMapper = new ObjectMapper();
        
        SecurityContextHolder.clearContext();
    }

    @Test
    void authenticateUser_success() throws Exception {
        AuthRequest request = new AuthRequest();
        request.setEmail("test@example.com");
        request.setPassword("password");

        User user = new User();
        user.setEmail("test@example.com");
        user.setRole(Role.SHOPPER);

        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn(org.springframework.security.core.userdetails.User
                .withUsername("test@example.com").password("password").roles("SHOPPER").build());

        when(loginAttemptTracker.isAccountLocked(eq("test@example.com"))).thenReturn(false);
        when(authenticationManager.authenticate(any())).thenReturn(auth);
        when(jwtUtil.generateToken(any())).thenReturn("mock-jwt-token");
        when(jwtUtil.generateRefreshToken(any())).thenReturn("mock-refresh-token");
        when(userService.getUserByEmail(eq("test@example.com"))).thenReturn(user);

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("mock-jwt-token"))
                .andExpect(jsonPath("$.refreshToken").value("mock-refresh-token"))
                .andExpect(jsonPath("$.email").value("test@example.com"))
                .andExpect(jsonPath("$.role").value("SHOPPER"));

        verify(loginAttemptTracker).recordSuccessfulAttempt("test@example.com");
    }

    @Test
    void authenticateUser_accountLocked() throws Exception {
        AuthRequest request = new AuthRequest();
        request.setEmail("test@example.com");
        request.setPassword("password");

        when(loginAttemptTracker.isAccountLocked(eq("test@example.com"))).thenReturn(true);
        when(loginAttemptTracker.getLockoutMessage(eq("test@example.com"))).thenReturn("Account is temporarily locked due to multiple failed login attempts");

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().is(423))
                .andExpect(jsonPath("$.error").exists())
                .andExpect(jsonPath("$.remainingAttempts").value("0"));
    }

    @Test
    void authenticateUser_invalidCredentials() throws Exception {
        AuthRequest request = new AuthRequest();
        request.setEmail("test@example.com");
        request.setPassword("wrong-password");

        when(loginAttemptTracker.isAccountLocked(eq("test@example.com"))).thenReturn(false);
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("Invalid credentials"));

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Invalid credentials"))
                .andExpect(jsonPath("$.remainingAttempts").exists());

        verify(loginAttemptTracker).recordFailedAttempt("test@example.com");
    }

    @Test
    void registerUser_success() throws Exception {
        UserCreateRequest request = new UserCreateRequest();
        request.setEmail("newuser@example.com");
        request.setPassword("password");
        request.setRole(Role.SHOPPER);

        User user = new User();
        user.setId("123");
        user.setEmail("newuser@example.com");
        user.setRole(Role.SHOPPER);

        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn(org.springframework.security.core.userdetails.User
                .withUsername("newuser@example.com").password("password").roles("SHOPPER").build());

        when(userService.emailExists(eq("newuser@example.com"))).thenReturn(false);
        when(userService.createUser(eq(request))).thenReturn(user);
        when(authenticationManager.authenticate(any())).thenReturn(auth);
        when(jwtUtil.generateToken(any())).thenReturn("mock-jwt-token");
        when(jwtUtil.generateRefreshToken(any())).thenReturn("mock-refresh-token");

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("mock-jwt-token"))
                .andExpect(jsonPath("$.refreshToken").value("mock-refresh-token"))
                .andExpect(jsonPath("$.email").value("newuser@example.com"))
                .andExpect(jsonPath("$.role").value("SHOPPER"));
    }

    @Test
    void registerUser_emailAlreadyExists() throws Exception {
        UserCreateRequest request = new UserCreateRequest();
        request.setEmail("existing@example.com");
        request.setPassword("password");

        when(userService.emailExists(eq("existing@example.com"))).thenReturn(true);

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Email is already taken!"));
    }

    @Test
    void logoutUser_success() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer mock-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        mockMvc.perform(post("/api/auth/logout")
                .header("Authorization", "Bearer mock-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("User logged out successfully"));

        verify(tokenBlacklist).blacklistToken(eq("mock-token"), anyLong());
    }
}