package com.example.springsecurityproject.security;

import com.example.springsecurityproject.constants.UserPermission;
import com.example.springsecurityproject.constants.UserRole;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.example.springsecurityproject.constants.UserPermission.*;
import static com.example.springsecurityproject.constants.UserRole.*;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
// this is needed because of @PreAuthorize annotation on the methods in the controller (proPostEnable is true by default)
public class Config {

    /* .formLogin uses login form with some html and css also it provides /login and /logout endpoints
       .httpBasic is also login form but without these endpoints and css */
    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        return http
                .csrf().disable()
                .authorizeHttpRequests()
                .requestMatchers("/").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/**").hasRole(STUDENT.name())
//                .requestMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .requestMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .requestMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .requestMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMIN_TRAINEE.name())
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .and()
                .rememberMe() // with formLogin we have a box with tick to check or uncheck before login
                .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21)) // extending Session with rememberMe
                .key("securityKey") //this is the key that is used to hash the content (username and expiration time)
                .and()
                .logout()
                /*this is what happens under the hood when we disable csrf, the "/logout" URL is GET method but usually if we want to have
                * the protection of csrf logout should be POST so when we enable csrf the logout URL becomes POST by default.
                * So this logoutRequestMatcher is used under the hood of Spring Security when csrf is disabled*/
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID", "remember-me")
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
