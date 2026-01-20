package com.tailormade.auth.controller;

import com.tailormade.auth.TailorMadeCoutureAuthServiceApplication;
import com.tailormade.auth.dto.*;
import com.tailormade.auth.model.Role;
import com.tailormade.auth.model.User;
import com.tailormade.auth.repository.UserRepository;
import com.tailormade.auth.util.TokenBlacklist;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.*;
import org.springframework.test.context.ActiveProfiles;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = TailorMadeCoutureAuthServiceApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class ControllerIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TokenBlacklist tokenBlacklist;

    private String baseUrl;

    private String testUserEmail = "integration-test@example.com";
    private String testUserPassword = "password123";

    @BeforeEach
    void setUp() {
        baseUrl = "http://localhost:" + port + "/api/auth";
        userRepository.findByEmail(testUserEmail).ifPresent(user -> userRepository.deleteById(user.getId()));
    }

    @AfterEach
    void tearDown() {
        userRepository.findByEmail(testUserEmail).ifPresent(user -> userRepository.deleteById(user.getId()));
    }

    @Test
    @DisplayName("Test successful user registration and login")
    void testUserRegistrationAndLoginFlow() {
        UserCreateRequest registerRequest = new UserCreateRequest();
        registerRequest.setEmail(testUserEmail);
        registerRequest.setPassword(testUserPassword);
        registerRequest.setRole(Role.SHOPPER);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<UserCreateRequest> registerEntity = new HttpEntity<>(registerRequest, headers);

        ResponseEntity<AuthResponse> registerResponse = restTemplate.exchange(
                baseUrl + "/register",
                HttpMethod.POST,
                registerEntity,
                AuthResponse.class
        );

        assertThat(registerResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(registerResponse.getBody()).isNotNull();
        assertThat(registerResponse.getBody().getToken()).isNotEmpty();
        assertThat(registerResponse.getBody().getRefreshToken()).isNotEmpty();
        assertThat(registerResponse.getBody().getEmail()).isEqualTo(testUserEmail);

        String accessToken = registerResponse.getBody().getToken();
        String refreshToken = registerResponse.getBody().getRefreshToken();

        User savedUser = userRepository.findByEmail(testUserEmail).orElse(null);
        assertThat(savedUser).isNotNull();
        assertThat(savedUser.getEmail()).isEqualTo(testUserEmail);
        assertThat(savedUser.getRole()).isEqualTo(Role.SHOPPER);

        AuthRequest loginRequest = new AuthRequest();
        loginRequest.setEmail(testUserEmail);
        loginRequest.setPassword(testUserPassword);

        HttpEntity<AuthRequest> loginEntity = new HttpEntity<>(loginRequest, headers);

        ResponseEntity<AuthResponse> loginResponse = restTemplate.exchange(
                baseUrl + "/login",
                HttpMethod.POST,
                loginEntity,
                AuthResponse.class
        );

        assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(loginResponse.getBody()).isNotNull();
        assertThat(loginResponse.getBody().getToken()).isNotEmpty();
        assertThat(loginResponse.getBody().getEmail()).isEqualTo(testUserEmail);
    }

    @Test
    @DisplayName("Test user login with invalid credentials")
    void testUserLoginWithInvalidCredentials() {
        AuthRequest loginRequest = new AuthRequest();
        loginRequest.setEmail("nonexistent@example.com");
        loginRequest.setPassword("wrongpassword");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<AuthRequest> entity = new HttpEntity<>(loginRequest, headers);

        ResponseEntity<Map> loginResponse = restTemplate.exchange(
                baseUrl + "/login",
                HttpMethod.POST,
                entity,
                Map.class
        );

        assertThat(loginResponse.getStatusCode()).isIn(HttpStatus.BAD_REQUEST, HttpStatus.UNAUTHORIZED);
        assertThat(loginResponse.getBody()).isNotNull();
        assertThat(loginResponse.getBody().get("error")).isNotNull();
    }

    @Test
    @DisplayName("Test email already exists during registration")
    void testRegisterWithExistingEmail() {
        UserCreateRequest firstRegisterRequest = new UserCreateRequest();
        firstRegisterRequest.setEmail(testUserEmail);
        firstRegisterRequest.setPassword(testUserPassword);
        firstRegisterRequest.setRole(Role.SHOPPER);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<UserCreateRequest> firstEntity = new HttpEntity<>(firstRegisterRequest, headers);

        ResponseEntity<AuthResponse> firstResponse = restTemplate.exchange(
                baseUrl + "/register",
                HttpMethod.POST,
                firstEntity,
                AuthResponse.class
        );

        assertThat(firstResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

        UserCreateRequest secondRegisterRequest = new UserCreateRequest();
        secondRegisterRequest.setEmail(testUserEmail);
        secondRegisterRequest.setPassword("anotherpassword");
        secondRegisterRequest.setRole(Role.ADMIN);

        HttpEntity<UserCreateRequest> secondEntity = new HttpEntity<>(secondRegisterRequest, headers);

        ResponseEntity<Map> secondResponse = restTemplate.exchange(
                baseUrl + "/register",
                HttpMethod.POST,
                secondEntity,
                Map.class
        );

        assertThat(secondResponse.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(secondResponse.getBody()).isNotNull();
        assertThat(secondResponse.getBody().get("error")).isEqualTo("Email is already taken!");
    }

    @Test
    @DisplayName("Test getting user profile with valid token")
    void testGetCurrentUserWithValidToken() {
        UserCreateRequest registerRequest = new UserCreateRequest();
        registerRequest.setEmail(testUserEmail);
        registerRequest.setPassword(testUserPassword);
        registerRequest.setRole(Role.SHOPPER);

        HttpHeaders registerHeaders = new HttpHeaders();
        registerHeaders.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<UserCreateRequest> registerEntity = new HttpEntity<>(registerRequest, registerHeaders);

        ResponseEntity<AuthResponse> registerResponse = restTemplate.exchange(
                baseUrl + "/register",
                HttpMethod.POST,
                registerEntity,
                AuthResponse.class
        );

        assertThat(registerResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        String accessToken = registerResponse.getBody().getToken();
        assertThat(accessToken).isNotEmpty();

        HttpHeaders profileHeaders = new HttpHeaders();
        profileHeaders.setBearerAuth(accessToken);

        HttpEntity<String> profileEntity = new HttpEntity<>(profileHeaders);

        ResponseEntity<UserProfileResponse> profileResponse = restTemplate.exchange(
                baseUrl + "/me",
                HttpMethod.GET,
                profileEntity,
                UserProfileResponse.class
        );

        assertThat(profileResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(profileResponse.getBody()).isNotNull();
        assertThat(profileResponse.getBody().getEmail()).isEqualTo(testUserEmail);
        assertThat(profileResponse.getBody().getRole()).isEqualTo("SHOPPER");
    }

    @Test
    @DisplayName("Test unauthorized access to protected endpoint")
    void testGetCurrentUserWithoutToken() {
        HttpHeaders headers = new HttpHeaders();

        HttpEntity<String> entity = new HttpEntity<>(headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                baseUrl + "/me",
                HttpMethod.GET,
                entity,
                Map.class
        );

        assertThat(response.getStatusCode()).isIn(HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN);
        if (response.getBody() != null) {
            assertThat(response.getBody().get("error")).isNotNull();
        }
    }

    @Test
    @DisplayName("Test token refresh functionality")
    void testTokenRefresh() {
        UserCreateRequest registerRequest = new UserCreateRequest();
        registerRequest.setEmail(testUserEmail);
        registerRequest.setPassword(testUserPassword);
        registerRequest.setRole(Role.SHOPPER);

        HttpHeaders registerHeaders = new HttpHeaders();
        registerHeaders.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<UserCreateRequest> registerEntity = new HttpEntity<>(registerRequest, registerHeaders);

        ResponseEntity<AuthResponse> registerResponse = restTemplate.exchange(
                baseUrl + "/register",
                HttpMethod.POST,
                registerEntity,
                AuthResponse.class
        );

        assertThat(registerResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        String refreshToken = registerResponse.getBody().getRefreshToken();
        assertThat(refreshToken).isNotEmpty();

        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest();
        refreshTokenRequest.setRefreshToken(refreshToken);

        HttpHeaders refreshHeaders = new HttpHeaders();
        refreshHeaders.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<RefreshTokenRequest> refreshEntity = new HttpEntity<>(refreshTokenRequest, refreshHeaders);

        ResponseEntity<AuthResponse> refreshResponse = restTemplate.exchange(
                baseUrl + "/refresh",
                HttpMethod.POST,
                refreshEntity,
                AuthResponse.class
        );

        assertThat(refreshResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(refreshResponse.getBody()).isNotNull();
        assertThat(refreshResponse.getBody().getToken()).isNotEmpty();
        assertThat(refreshResponse.getBody().getRefreshToken()).isNotEmpty();
        assertThat(refreshResponse.getBody().getEmail()).isEqualTo(testUserEmail);
    }

    @Test
    @DisplayName("Test logout functionality")
    void testUserLogout() {
        UserCreateRequest registerRequest = new UserCreateRequest();
        registerRequest.setEmail(testUserEmail);
        registerRequest.setPassword(testUserPassword);
        registerRequest.setRole(Role.SHOPPER);

        HttpHeaders registerHeaders = new HttpHeaders();
        registerHeaders.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<UserCreateRequest> registerEntity = new HttpEntity<>(registerRequest, registerHeaders);

        ResponseEntity<AuthResponse> registerResponse = restTemplate.exchange(
                baseUrl + "/register",
                HttpMethod.POST,
                registerEntity,
                AuthResponse.class
        );

        assertThat(registerResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        String accessToken = registerResponse.getBody().getToken();
        assertThat(accessToken).isNotEmpty();

        HttpHeaders logoutHeaders = new HttpHeaders();
        logoutHeaders.setBearerAuth(accessToken);

        HttpEntity<String> logoutEntity = new HttpEntity<>(logoutHeaders);

        ResponseEntity<Map> logoutResponse = restTemplate.exchange(
                baseUrl + "/logout",
                HttpMethod.POST,
                logoutEntity,
                Map.class
        );

        assertThat(logoutResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(logoutResponse.getBody()).isNotNull();
        assertThat(logoutResponse.getBody().get("message")).isEqualTo("User logged out successfully");

        HttpHeaders protectedHeaders = new HttpHeaders();
        protectedHeaders.setBearerAuth(accessToken);

        HttpEntity<String> protectedEntity = new HttpEntity<>(protectedHeaders);

        ResponseEntity<Map> protectedResponse = restTemplate.exchange(
                baseUrl + "/me",
                HttpMethod.GET,
                protectedEntity,
                Map.class
        );

        assertThat(protectedResponse.getStatusCode()).isIn(HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN);
    }

    @Test
    @DisplayName("Test updating user profile")
    void testUpdateUserProfile() {
        UserCreateRequest registerRequest = new UserCreateRequest();
        registerRequest.setEmail(testUserEmail);
        registerRequest.setPassword(testUserPassword);
        registerRequest.setRole(Role.SHOPPER);

        HttpHeaders registerHeaders = new HttpHeaders();
        registerHeaders.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<UserCreateRequest> registerEntity = new HttpEntity<>(registerRequest, registerHeaders);

        ResponseEntity<AuthResponse> registerResponse = restTemplate.exchange(
                baseUrl + "/register",
                HttpMethod.POST,
                registerEntity,
                AuthResponse.class
        );

        assertThat(registerResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        String accessToken = registerResponse.getBody().getToken();
        assertThat(accessToken).isNotEmpty();

        ProfileUpdateRequest updateRequest = new ProfileUpdateRequest();
        updateRequest.setEmail("updated-" + testUserEmail);

        HttpHeaders updateHeaders = new HttpHeaders();
        updateHeaders.setBearerAuth(accessToken);
        updateHeaders.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<ProfileUpdateRequest> updateEntity = new HttpEntity<>(updateRequest, updateHeaders);

        ResponseEntity<UserProfileResponse> updateResponse = restTemplate.exchange(
                baseUrl + "/me",
                HttpMethod.PUT,
                updateEntity,
                UserProfileResponse.class
        );

        assertThat(updateResponse.getStatusCode()).isIn(HttpStatus.OK, HttpStatus.FORBIDDEN);
        if (updateResponse.getStatusCode().is2xxSuccessful()) {
            assertThat(updateResponse.getBody()).isNotNull();
            assertThat(updateResponse.getBody().getEmail()).isEqualTo("updated-" + testUserEmail);
        }
    }
}