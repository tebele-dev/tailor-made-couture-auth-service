package com.tailormade.auth;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.*;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class ControllerIntegrationTest {

    @LocalServerPort
    private int port;

    private final RestTemplate restTemplate = new RestTemplate();

    private String getBaseUrl() {
        return "http://localhost:" + port + "/api/auth";
    }

    @Test
    void testRegisterAndLoginEndpoints() {

        String uniqueEmail = "integration" + System.currentTimeMillis() + "@test.com";
        

        String registerJson = String.format(
            "{\"email\":\"%s\",\"password\":\"SecurePass123!\",\"role\":\"SHOPPER\"}",
            uniqueEmail
        );

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<String> registerEntity = new HttpEntity<>(registerJson, headers);
        
        ResponseEntity<String> registerResponse = restTemplate.postForEntity(
            getBaseUrl() + "/register", 
            registerEntity, 
            String.class
        );

        assertEquals(HttpStatus.OK, registerResponse.getStatusCode());
        assertNotNull(registerResponse.getBody());
        assertTrue(registerResponse.getBody().contains("\"token\""));
        assertTrue(registerResponse.getBody().contains("\"refreshToken\""));
        assertTrue(registerResponse.getBody().contains("\"email\":\"" + uniqueEmail + "\""));
        assertTrue(registerResponse.getBody().contains("\"role\":\"SHOPPER\""));


        String loginJson = String.format(
            "{\"email\":\"%s\",\"password\":\"SecurePass123!\"}",
            uniqueEmail
        );

        HttpEntity<String> loginEntity = new HttpEntity<>(loginJson, headers);
        
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(
            getBaseUrl() + "/login", 
            loginEntity, 
            String.class
        );

        assertEquals(HttpStatus.OK, loginResponse.getStatusCode());
        assertNotNull(loginResponse.getBody());
        assertTrue(loginResponse.getBody().contains("\"token\""));
        assertTrue(loginResponse.getBody().contains("\"refreshToken\""));
        assertTrue(loginResponse.getBody().contains("\"email\":\"" + uniqueEmail + "\""));
        assertTrue(loginResponse.getBody().contains("\"role\":\"SHOPPER\""));
    }

    @Test
    void testDuplicateRegistration() {
        String uniqueEmail = "duplicate" + System.currentTimeMillis() + "@test.com";
        
        String json = String.format(
            "{\"email\":\"%s\",\"password\":\"SecurePass123!\",\"role\":\"SHOPPER\"}",
            uniqueEmail
        );

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<String> entity = new HttpEntity<>(json, headers);
        
        try {

            ResponseEntity<String> firstResponse = restTemplate.postForEntity(
                getBaseUrl() + "/register", 
                entity, 
                String.class
            );
            assertEquals(HttpStatus.OK, firstResponse.getStatusCode());


            restTemplate.postForEntity(getBaseUrl() + "/register", entity, String.class);
            fail("Expected HttpClientErrorException for duplicate registration");
            
        } catch (HttpClientErrorException e) {

            assertEquals(HttpStatus.BAD_REQUEST, e.getStatusCode());
            assertTrue(e.getResponseBodyAsString().contains("Email is already taken!"));
        }
    }

    @Test
    void testInvalidLogin() {
        String uniqueEmail = "nonexistent" + System.currentTimeMillis() + "@test.com";
        
        String json = String.format(
            "{\"email\":\"%s\",\"password\":\"wrongpassword\"}",
            uniqueEmail
        );

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<String> entity = new HttpEntity<>(json, headers);
        
        try {

            restTemplate.postForEntity(getBaseUrl() + "/login", entity, String.class);
            fail("Expected HttpClientErrorException for invalid login");
            
        } catch (HttpClientErrorException e) {

            assertEquals(HttpStatus.BAD_REQUEST, e.getStatusCode());
            assertTrue(e.getResponseBodyAsString().contains("Invalid credentials"));
        }
    }

    @Test
    void testRegisterValidation() {

        String json = "{\"email\":\"invalid-email\",\"password\":\"short\",\"role\":\"SHOPPER\"}";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<String> entity = new HttpEntity<>(json, headers);
        
        try {

            restTemplate.postForEntity(getBaseUrl() + "/register", entity, String.class);
            fail("Expected HttpClientErrorException for validation error");
            
        } catch (HttpClientErrorException e) {

            assertTrue(e.getStatusCode().is4xxClientError());
            System.out.println("Validation test received: " + e.getStatusCode() + " - " + e.getResponseBodyAsString());
        }
    }

    @Test
    void testLoginValidation() {

        String json = "{\"email\":\"\",\"password\":\"Password123!\"}";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<String> entity = new HttpEntity<>(json, headers);
        
        try {

            restTemplate.postForEntity(getBaseUrl() + "/login", entity, String.class);
            fail("Expected HttpClientErrorException for validation error");
            
        } catch (HttpClientErrorException e) {

            assertTrue(e.getStatusCode().is4xxClientError());
            System.out.println("Validation test received: " + e.getStatusCode() + " - " + e.getResponseBodyAsString());
        }
    }
}