package com.example.springsecurityjwt.controllers;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@Slf4j
public class OAuthGoogleTestController {

    @GetMapping("/")
    public String test(Authentication authentication) {
        log.info(String.valueOf(authentication));
        log.info(String.valueOf(authentication.getPrincipal()));
        return "Successfully logged with Google Acc.!";
    }

    @GetMapping("person-list")
    public List<Person> retrieve() {
        return List.of(
                new Person("Georgi", "Tangardzhiev"),
                new Person("Georgi", "Kyshenko"),
                new Person("Georgi", "Evtimov"));
    }
}

record Person(String firstName, String lastName) {
}
