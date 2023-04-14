package com.example.springsecurityproject.models;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

@AllArgsConstructor
@Getter
@ToString
public class Student {

    private long id;
    private String studentName;
}
