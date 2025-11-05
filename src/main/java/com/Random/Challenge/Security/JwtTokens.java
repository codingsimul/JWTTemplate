package com.docker.jwt.Security;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.ResponseCookie;

@AllArgsConstructor
@Getter
public class JwtTokens {
    String accessToken;
    ResponseCookie refreshCookie;
}
