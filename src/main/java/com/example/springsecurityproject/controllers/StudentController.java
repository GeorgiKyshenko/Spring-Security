package com.example.springsecurityproject.controllers;

import com.example.springsecurityproject.models.Student;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("api/students")
public class StudentController {

    private static final List<Student> students = List.of(
            new Student(1, "Georgi"),
            new Student(2, "Kyshenko"),
            new Student(3, "Daniel")
    );

    @GetMapping("{studentId}")
    public Student getStudent(@PathVariable long studentId) {
        return students.stream().filter(student -> student.getId() == studentId).findFirst().orElseThrow(
                ()-> new IllegalStateException("User doesnt exists")
        );
    }
}
