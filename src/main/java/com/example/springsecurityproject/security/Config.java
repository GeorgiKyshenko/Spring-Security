package com.example.springsecurityproject.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class Config {

    /* .formLogin uses login for with some html and css also it provides /login and /logout endpoints
       .httpBasic is also login form but without these endpoints and css */
    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests()
                .requestMatchers("/").permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .and()
                .build();
    }

    //override the default user with our own created user
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails defaultUser = User.builder()
                .username("Georgi")
                .password(encoder().encode("12345"))
                .roles("STUDENT")
                .build();

        UserDetails defaultUser2 = User.builder()
                .username("Kyshenko")
                .password(encoder().encode("123"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(defaultUser, defaultUser2);
    }

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder(10); // ten times to hash the password
    }
}
