package com.example.springsecurityproject.security;

import com.example.springsecurityproject.constants.UserPermission;
import com.example.springsecurityproject.constants.UserRole;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static com.example.springsecurityproject.constants.UserPermission.*;
import static com.example.springsecurityproject.constants.UserRole.*;

@Configuration
@EnableWebSecurity
public class Config {

    /* .formLogin uses login for with some html and css also it provides /login and /logout endpoints
       .httpBasic is also login form but without these endpoints and css */
    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        return http
                .csrf().disable()
                .authorizeHttpRequests()
                .requestMatchers("/").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/**").hasRole(STUDENT.name())
                .requestMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .requestMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .requestMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .requestMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMIN_TRAINEE.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic()
                .and()
                .build();
    }

    //override the default user with our own created user
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails studentUser = User.builder()
                .username("Georgi")
                .password(encoder().encode("123"))
//                .roles(STUDENT.name())
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails adminUser = User.builder()
                .username("Kyshenko")
                .password(encoder().encode("123"))
//              .roles(ADMIN.name())
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails adminTraineeUser = User.builder()
                .username("Admin Trainee")
                .password(encoder().encode("123"))
//              .roles(ADMIN_TRAINEE.name())
                .authorities(ADMIN_TRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(studentUser, adminUser, adminTraineeUser);
    }

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder(10); // ten times to hash the password
    }
}
