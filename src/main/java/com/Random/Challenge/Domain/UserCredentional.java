package com.docker.jwt.Domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor
public class UserCredentional {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JoinColumn( name = "user_id", nullable = false) //fk, 주인
    @JsonIgnore
    private User user;

    private String password;

    public UserCredentional(String password) {this.password = password;}

    public void setUser(User user){this.user=user;}

    public void setPassword(String password) {this.password = password;}
}
