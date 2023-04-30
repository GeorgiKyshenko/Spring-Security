package com.example.springsecurityjwt.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
public class JWTAuthenticationResource {

    private final JwtEncoder jwtEncoder;

    /*First we use Basic Authentication to access the "/authenticate" URL, then it generates JWT Token, and we use it as
    * an authentication setting Bearer Token auth!*/ 
    @PostMapping("/authenticate")
    public JwtResponse authenticate(Authentication authentication) {
        return new JwtResponse(createToken(authentication));
    }

    private String createToken(Authentication authentication) {
        var claims = JwtClaimsSet
                .builder()
                .issuer("self")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60 * 15))
                .subject(authentication.getName())
                .claim("scope", createScope(authentication))
                .build();

        JwtEncoderParameters params = JwtEncoderParameters.from(claims);
        return jwtEncoder.encode(params).getTokenValue();
    }

    private String createScope(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
    }
}

record JwtResponse(String token) {
}
