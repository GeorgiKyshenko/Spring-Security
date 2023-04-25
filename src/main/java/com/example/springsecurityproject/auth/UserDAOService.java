package com.example.springsecurityproject.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.springsecurityproject.constants.UserRole.ADMIN;
import static com.example.springsecurityproject.constants.UserRole.STUDENT;

@RequiredArgsConstructor
@Repository("fakeRepo")
public class UserDAOService implements UserDAO {

    private final PasswordEncoder passwordEncoder;

    @Override
    public Optional<User> getUserByUsername(String username) {
        return getUsers()
                .stream()
                .filter(user -> username.equals(user.getUsername()))
                .findFirst();
    }

    public List<User> getUsers() {

        return List.of(
                new User(
                        "Petko",
                        passwordEncoder.encode("123"),
                        STUDENT.getGrantedAuthorities().stream().toList(),
                        true, true, true, true),
                new User(
                        "Martin",
                        passwordEncoder.encode("123"),
                        ADMIN.getGrantedAuthorities().stream().toList(),
                        true, true, true, true));
    }
}
