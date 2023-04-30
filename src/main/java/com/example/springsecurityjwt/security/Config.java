package com.example.springsecurityjwt.security;

import io.micrometer.common.lang.NonNull;
import io.micrometer.common.lang.NonNullApi;
import jakarta.annotation.Nonnull;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.sql.DataSource;
import java.util.List;

//@Configuration
//@EnableWebSecurity
public class Config {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth ->
                auth.requestMatchers(AntPathRequestMatcher.antMatcher("/h2/**")).permitAll() //this is the new way to avoid Spring Sec h2-permitAll
                        .anyRequest().authenticated());
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//        http.formLogin();
        http.httpBasic();
        http.csrf().disable().headers().frameOptions().disable();
        return http.build();
    }

    /*this data source is created by default but not with that exact script so in this bean we are creating our own
     * data source bean with JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION script which creates few tables in the DB */
    @Bean
    public DataSource dataSource() {
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }

    /*another way of creating hardcoded Users with JdbcUserDetailsManager and DataSource instead of ->
        InMemoryUserDetailsManager*/
//    @Bean
//    public UserDetailsService userDetailsService(DataSource dataSource) {
//
//        /*this {noop} is because when we use basic auth form. When we submit our password Spring Sec requires a password encoder
//        * with {noop} we dodge it without pass enc and the actual password is 123. {noop} DOES NOT WORK WITH formLogin, and we have to use BCrypt!!!*/
//        UserDetails trainee = User.withUsername("trainee")
//                .password(encoder().encode("123"))
//                .roles("TRAINEE")
//                .build();
//
//        UserDetails admin = User.withUsername("admin")
//                .password(encoder().encode("123"))
//                .roles("ADMIN")
//                .build();
//
//        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
//        jdbcUserDetailsManager.createUser(trainee);
//        jdbcUserDetailsManager.createUser(admin);
//
//        return jdbcUserDetailsManager;
//    }
//
//    @Bean
//    public PasswordEncoder encoder() {
//        return new BCryptPasswordEncoder(12);
//    }

    /*or we can go to the controller we want and annotated it with @CrossOrigin() we can specify the domain in the scope
     * otherwise it allows any domain to send requests */
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**") // allow request to all URLs
                        .allowedMethods("*") // with all Http methods (GET-POST-DELETE etc)
                        .allowedOrigins("http://localhost:3000");  // from this domain
            }
        };
    }

    /* another way of configuration
    @Bean
    CorsConfigurationSource corsConfigurationSource(){
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOrigins(List.of("https://sf073-green-fe.netlify.app/", "http://localhost:3000/"));
        corsConfiguration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        corsConfiguration.setAllowedHeaders(List.of("*"));
        corsConfiguration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);
        return source;
    }
     */
}
