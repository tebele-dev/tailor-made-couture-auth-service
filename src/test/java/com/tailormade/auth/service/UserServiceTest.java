package com.tailormade.auth.service;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.mockito.ArgumentMatchers.any;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.tailormade.auth.dto.ProfileUpdateRequest;
import com.tailormade.auth.dto.UserCreateRequest;
import com.tailormade.auth.model.Role;
import com.tailormade.auth.model.User;
import com.tailormade.auth.repository.UserRepository;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserService userService;

    private UserCreateRequest userCreateRequest;
    private User user;

    @BeforeEach
    void setUp() {
        userCreateRequest = new UserCreateRequest();
        userCreateRequest.setEmail("test@example.com");
        userCreateRequest.setPassword("password123");
        userCreateRequest.setRole(Role.SHOPPER);

        user = new User();
        user.setId("user123");
        user.setEmail("test@example.com");
        user.setPassword("encodedPassword");
        user.setRole(Role.SHOPPER);
        user.setEnabled(true);
    }

    @Test
    void createUser_success() {
        when(userRepository.existsByEmail("test@example.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("encodedPassword");
        when(userRepository.save(any(User.class))).thenReturn(user);

        User result = userService.createUser(userCreateRequest);

        assertThat(result).isNotNull();
        assertThat(result.getEmail()).isEqualTo("test@example.com");
        assertThat(result.getRole()).isEqualTo(Role.SHOPPER);
        assertThat(result.isEnabled()).isTrue();
        
        verify(userRepository).existsByEmail("test@example.com");
        verify(passwordEncoder).encode("password123");
        verify(userRepository).save(any(User.class));
    }

    @Test
    void createUser_withNullRole_defaultsToShopper() {
        userCreateRequest.setRole(null);
        when(userRepository.existsByEmail("test@example.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("encodedPassword");
        User shopperUser = new User();
        shopperUser.setId("user123");
        shopperUser.setEmail("test@example.com");
        shopperUser.setPassword("encodedPassword");
        shopperUser.setRole(Role.SHOPPER);
        shopperUser.setEnabled(true);
        when(userRepository.save(any(User.class))).thenReturn(shopperUser);

        User result = userService.createUser(userCreateRequest);

        assertThat(result.getRole()).isEqualTo(Role.SHOPPER);
    }

    @Test
    void createUser_emailAlreadyExists_throwsException() {
        when(userRepository.existsByEmail("test@example.com")).thenReturn(true);

        assertThatThrownBy(() -> userService.createUser(userCreateRequest))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Email already registered");

        verify(userRepository).existsByEmail("test@example.com");
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void getUserByEmail_success() {
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));

        User result = userService.getUserByEmail("test@example.com");

        assertThat(result).isNotNull();
        assertThat(result.getEmail()).isEqualTo("test@example.com");
        verify(userRepository).findByEmail("test@example.com");
    }

    @Test
    void getUserByEmail_notFound_throwsException() {
        when(userRepository.findByEmail("nonexistent@example.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.getUserByEmail("nonexistent@example.com"))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("User not found with email: nonexistent@example.com");

        verify(userRepository).findByEmail("nonexistent@example.com");
    }

    @Test
    void emailExists_returnsTrue_whenEmailExists() {
        when(userRepository.existsByEmail("existing@example.com")).thenReturn(true);

        boolean result = userService.emailExists("existing@example.com");

        assertThat(result).isTrue();
        verify(userRepository).existsByEmail("existing@example.com");
    }

    @Test
    void emailExists_returnsFalse_whenEmailDoesNotExist() {
        when(userRepository.existsByEmail("new@example.com")).thenReturn(false);

        boolean result = userService.emailExists("new@example.com");

        assertThat(result).isFalse();
        verify(userRepository).existsByEmail("new@example.com");
    }

    @Test
    void updateUser_emailOnly_success() {
        ProfileUpdateRequest updateRequest = new ProfileUpdateRequest();
        updateRequest.setEmail("newemail@example.com");
        
        User existingUser = new User();
        existingUser.setId("user123");
        existingUser.setEmail("test@example.com");
        existingUser.setPassword("encodedPassword");
        existingUser.setRole(Role.SHOPPER);
        existingUser.setEnabled(true);
        
        User updatedUser = new User();
        updatedUser.setId("user123");
        updatedUser.setEmail("newemail@example.com");
        updatedUser.setPassword("encodedPassword");
        updatedUser.setRole(Role.SHOPPER);
        updatedUser.setEnabled(true);
        
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(existingUser));
        when(userRepository.existsByEmail("newemail@example.com")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenReturn(updatedUser);

        User result = userService.updateUser("test@example.com", updateRequest);

        assertThat(result).isNotNull();
        assertThat(result.getEmail()).isEqualTo("newemail@example.com");
        verify(userRepository).findByEmail("test@example.com");
        verify(userRepository).existsByEmail("newemail@example.com");
        verify(userRepository).save(any(User.class));
    }

    @Test
    void updateUser_passwordOnly_success() {
        ProfileUpdateRequest updateRequest = new ProfileUpdateRequest();
        updateRequest.setCurrentPassword("oldpassword");
        updateRequest.setNewPassword("newpassword");
        
        User existingUser = new User();
        existingUser.setId("user123");
        existingUser.setEmail("test@example.com");
        existingUser.setPassword("encodedOldPassword");
        existingUser.setRole(Role.SHOPPER);
        existingUser.setEnabled(true);
        
        User updatedUser = new User();
        updatedUser.setId("user123");
        updatedUser.setEmail("test@example.com");
        updatedUser.setPassword("encodedNewPassword");
        updatedUser.setRole(Role.SHOPPER);
        updatedUser.setEnabled(true);
        
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(existingUser));
        when(passwordEncoder.encode("newpassword")).thenReturn("encodedNewPassword");
        when(userRepository.save(any(User.class))).thenReturn(updatedUser);

        User result = userService.updateUser("test@example.com", updateRequest);

        assertThat(result).isNotNull();
        assertThat(result.getPassword()).isEqualTo("encodedNewPassword");
        verify(passwordEncoder).encode("newpassword");
        verify(userRepository).save(any(User.class));
    }

    @Test
    void updateUser_emailAlreadyTaken_throwsException() {
        ProfileUpdateRequest updateRequest = new ProfileUpdateRequest();
        updateRequest.setEmail("taken@example.com");
        
        User existingUser = new User();
        existingUser.setId("user123");
        existingUser.setEmail("test@example.com");
        existingUser.setPassword("encodedPassword");
        existingUser.setRole(Role.SHOPPER);
        existingUser.setEnabled(true);
        
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(existingUser));
        when(userRepository.existsByEmail("taken@example.com")).thenReturn(true);

        assertThatThrownBy(() -> userService.updateUser("test@example.com", updateRequest))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Email is already taken!");

        verify(userRepository).findByEmail("test@example.com");
        verify(userRepository).existsByEmail("taken@example.com");
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void deleteUser_success() {
        User existingUser = new User();
        existingUser.setId("user123");
        existingUser.setEmail("test@example.com");
        existingUser.setPassword("encodedPassword");
        existingUser.setRole(Role.SHOPPER);
        existingUser.setEnabled(true);
        
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(existingUser));
        
        userService.deleteUser("test@example.com");
        
        verify(userRepository).findByEmail("test@example.com");
        verify(userRepository).delete(existingUser);
    }

    @Test
    void getUserById_success() {
        when(userRepository.findById("user123")).thenReturn(Optional.of(user));

        User result = userService.getUserById("user123");

        assertThat(result).isNotNull();
        assertThat(result.getId()).isEqualTo("user123");
        assertThat(result.getEmail()).isEqualTo("test@example.com");
        verify(userRepository).findById("user123");
    }

    @Test
    void getUserById_notFound_throwsException() {
        when(userRepository.findById("nonexistent")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.getUserById("nonexistent"))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("User not found with ID: nonexistent");

        verify(userRepository).findById("nonexistent");
    }
}
