package com.example.springsecurityproject.constants;

import com.google.common.collect.Sets;

import java.util.Set;

import static com.example.springsecurityproject.constants.UserPermission.*;

public enum UserRole {
    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(COURSE_READ,COURSE_WRITE,STUDENT_READ, STUDENT_WRITE));  // static import of UserPermission
    private final Set<UserPermission> permissions;

    UserRole(Set<UserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<UserPermission> getPermissions() {
        return permissions;
    }
}
