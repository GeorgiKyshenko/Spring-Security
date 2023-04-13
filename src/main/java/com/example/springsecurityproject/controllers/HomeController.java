package com.example.springsecurityproject.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @GetMapping("/")
    public String welcomePage() {
        return "Welcome Page Controller";
    }
}
