package com.tailormade.auth.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.tailormade.auth.dto.ProfileUpdateRequest;
import com.tailormade.auth.dto.UserCreateRequest;
import com.tailormade.auth.model.Role;
import com.tailormade.auth.model.User;
import com.tailormade.auth.repository.UserRepository;


@Service
@Transactional
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;



    public User createUser(UserCreateRequest request) {
        logger.info("Creating user with email: {}", request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            logger.warn("Email already registered: {}", request.getEmail());
            throw new RuntimeException("Email already registered");
        }



        User user = new User();
        user.setEmail(request.getEmail());
        logger.debug("Encoding password for user: {}", request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(request.getRole() != null ? request.getRole() : Role.SHOPPER);
        user.setEnabled(true);

        User savedUser = userRepository.save(user);
        logger.info("User created successfully: {} with ID: {}", savedUser.getEmail(), savedUser.getId());
        return savedUser;
    }

    public User getUserByEmail(String email) {
        logger.debug("Fetching user by email: {}", email);
        return userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    logger.warn("User not found with email: {}", email);
                    return new RuntimeException("User not found with email: " + email);
                });
    }

    public boolean emailExists(String email) {
        logger.debug("Checking if email exists: {}", email);
        boolean exists = userRepository.existsByEmail(email);
        logger.debug("Email {} exists: {}", email, exists);
        return exists;
    }

    public User updateUser(String email, ProfileUpdateRequest request) {
        logger.info("Updating user profile for email: {}", email);
        
        User user = getUserByEmail(email);
        

        if (request.getEmail() != null && !request.getEmail().isEmpty()) {
            if (!request.getEmail().equals(email) && emailExists(request.getEmail())) {
                logger.warn("Email already taken: {}", request.getEmail());
                throw new RuntimeException("Email is already taken!");
            }
            user.setEmail(request.getEmail());
            logger.debug("Email updated to: {}", request.getEmail());
        }
        

        if (request.getNewPassword() != null && !request.getNewPassword().isEmpty()) {
            user.setPassword(passwordEncoder.encode(request.getNewPassword()));
            logger.debug("Password updated for user: {}", email);
        }
        
        user.setUpdatedAt(java.time.LocalDateTime.now());
        User updatedUser = userRepository.save(user);
        logger.info("User profile updated successfully: {}", updatedUser.getEmail());
        return updatedUser;
    }

    public void deleteUser(String email) {
        logger.info("Deleting user account: {}", email);
        User user = getUserByEmail(email);
        userRepository.delete(user);
        logger.info("User account deleted successfully: {}", email);
    }

    public User getUserById(String id) {
        logger.debug("Fetching user by ID: {}", id);
        return userRepository.findById(id)
                .orElseThrow(() -> {
                    logger.warn("User not found with ID: {}", id);
                    return new RuntimeException("User not found with ID: " + id);
                });
    }
}
