package com.example.springsecurityproject.controllers;

import com.example.springsecurityproject.models.Student;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("management/api/students")
public class StudentManagementController {

    private static final List<Student> students = List.of(
            new Student(1, "Georgi"),
            new Student(2, "Kyshenko"),
            new Student(3, "Admin Trainee")
    );

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_ADMIN_TRAINEE')")
    public List<Student> getAllStudents() {
        return students;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")
    public void registerNewStudent(@RequestBody Student student) {
        log.info(String.valueOf(student));
    }

    @DeleteMapping("/{studentId}")
    public void deleteStudent(@PathVariable long studentId) {
        log.info(String.valueOf(studentId));
    }

    @PutMapping("/{studentId}")
    public void updateStudent(@PathVariable long studentId, @RequestBody Student student) {
        log.info("{}, {}", studentId, student);
    }
}
