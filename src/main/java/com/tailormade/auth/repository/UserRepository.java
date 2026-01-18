package com.tailormade.auth.repository;

import com.tailormade.auth.model.Role;
import com.tailormade.auth.model.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends MongoRepository<User, String> {

    Optional<User> findByEmail(String email);

    Boolean existsByEmail(String email);

    List<User> findByRole(Role role);

    List<User> findByEnabled(boolean enabled);

    List<User> findByEmailContainingIgnoreCase(String email);

    long countByRole(Role role);
}
