package com.example.springsecurityproject.services;

import com.example.springsecurityproject.auth.UserDAO;
import com.example.springsecurityproject.auth.UserDAOService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserService implements UserDetailsService {

    private final UserDAOService userDAOService;

    @Autowired
    public UserService(UserDAOService userDAOService) {
        this.userDAOService = userDAOService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userDAOService
                .getUserByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(String.format("User %s not found!", username)));
    }
}
