package com.docker.jwt.Controller;

import com.docker.jwt.Dto.SignInRequest;
import com.docker.jwt.Dto.SignUpRequest;
import com.docker.jwt.Dto.SignUpResponse;
import com.docker.jwt.Service.UserService;
import com.docker.jwt.Security.JwtTokens;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/user")
@RequiredArgsConstructor
public class UserController {
    public final UserService userService;

    @PostMapping("/signUp")
    public ResponseEntity<SignUpResponse> signUp(@RequestBody SignUpRequest signUpRequest) {
        SignUpResponse signUpResponse = userService.signUp(
                        signUpRequest.getUsername(), signUpRequest.getPassword(), signUpRequest.getEmail());
        return ResponseEntity.ok().body(signUpResponse);
    }

    @PostMapping("/signIn")
    public ResponseEntity signIn(@RequestBody SignInRequest signInRequest){
        JwtTokens tokens = userService.signIn(
                signInRequest.getEmail(), signInRequest.getPassword());

        return ResponseEntity.ok()
                .header(HttpHeaders.AUTHORIZATION, "Bearer "+ tokens.getAccessToken())
                .header(HttpHeaders.SET_COOKIE, tokens.getRefreshCookie().toString())
                .build();
    }
    @GetMapping("/hello")
    public ResponseEntity hello(){
        return ResponseEntity.ok().body("hello");
    }
}