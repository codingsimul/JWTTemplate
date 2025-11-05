package com.docker.jwt.Security;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Role {
    USER("ROLE_USER"),
    ADMIN("ROLE_USER, ROLE_ADMIN");

    private final String roles;

    public static String getRoles(String role){
        return Role.valueOf(role).getRoles();
    }
}
