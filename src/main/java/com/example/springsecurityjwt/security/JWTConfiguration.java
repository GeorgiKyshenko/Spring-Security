package com.example.springsecurityjwt.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class JWTConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth ->
                auth.requestMatchers(AntPathRequestMatcher.antMatcher("/h2/**")).permitAll() //this is the new way to avoid Spring Sec h2-permitAll
                        .anyRequest().authenticated());
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//        http.formLogin();
        http.httpBasic();
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
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

    /*this is a configuration for JWT encoding/decoding*/
    @Bean
    public KeyPair keyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); //key size 2048 bits RSA encryption
        return keyPairGenerator.generateKeyPair();
    }

    @Bean
    public RSAKey rsaKey(KeyPair keyPair) {
        return new RSAKey
                .Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
        JWKSet jwkSet = new JWKSet(rsaKey);
        return ((jwkSelector, context) -> jwkSelector.select(jwkSet));

        /* that is the longest line of code to implement the JWKSource. We better use the lambda function.
        So in the JWKSource we can return a set of RSA Keys
        var jwkSource = new JWKSource<>() {
            @Override
            public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
                return jwkSelector.select(jwkSet);
            }
        };
        return jwkSource;

         */
    }

    @Bean
    public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
        return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey())
                .build();
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    /*another way of creating hardcoded Users with JdbcUserDetailsManager and DataSource instead of ->
        InMemoryUserDetailsManager*/
    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {

        /*this {noop} is because when we use basic auth form. When we submit our password Spring Sec requires a password encoder
         * with {noop} we dodge it without pass enc and the actual password is 123. {noop} DOES NOT WORK WITH formLogin, and we have to use BCrypt!!!*/
        UserDetails trainee = User.withUsername("trainee")
                .password(encoder().encode("123"))
                .roles("TRAINEE")
                .build();

        UserDetails admin = User.withUsername("admin")
                .password(encoder().encode("123"))
                .roles("ADMIN")
                .build();

        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(trainee);
        jdbcUserDetailsManager.createUser(admin);

        return jdbcUserDetailsManager;
    }

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder(12);
    }

}
