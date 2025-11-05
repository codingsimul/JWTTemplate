package com.docker.jwt.Dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Date;

@Getter
@AllArgsConstructor
public class SignUpResponse{
    String username;
    Date creationAt;
}
