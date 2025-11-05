package com.docker.jwt.Domain;

import jakarta.annotation.Nullable;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@NoArgsConstructor
@Getter
public class User {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;
    private String email;

    private String roles;

    @OneToOne(mappedBy = "user",cascade = CascadeType.ALL)
    private UserCredentional userCredentional;

    public User(String username, String email, String role, UserCredentional userCredentional) {
        this.username = username;
        this.email = email;
        this.roles = role;
        this.userCredentional = userCredentional;
    }
}
