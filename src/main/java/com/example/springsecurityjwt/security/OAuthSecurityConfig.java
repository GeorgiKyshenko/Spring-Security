package com.example.springsecurityjwt.security;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class OAuthSecurityConfig {

    /*We create a test API on Google API Console with this filter chain configuration, and we can connect to
     localhost:8080 via real gmail account. For this configuration to work properly I had to comment all the code in
     JWTConfiguration also the classes related to JWT*/
    @Bean
    @Order(SecurityProperties.BASIC_AUTH_ORDER)
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests().anyRequest().authenticated();
        http.oauth2Login();
        return http.build();
    }
}
