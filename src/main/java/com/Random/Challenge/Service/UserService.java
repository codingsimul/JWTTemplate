package com.docker.jwt.Service;

import com.docker.jwt.Domain.User;
import com.docker.jwt.Domain.UserCredentional;
import com.docker.jwt.Dto.SignUpResponse;
import com.docker.jwt.Repository.UserRepository;
import com.docker.jwt.Security.JwtProvider;
import com.docker.jwt.Security.JwtTokens;
import com.docker.jwt.Security.Role;
import com.docker.jwt.Security.TokenType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    public SignUpResponse signUp(String username, String password, String email) {
        // 1. 신규 가입인지 확인
        // 2. 비밀번호 해싱
        // 3. user 추가
        userRepository.findByEmail(email).ifPresent(
                u -> {throw new RuntimeException("User with email " + email + " already exists");});

        String encodingPassword = passwordEncoder.encode(password);

        User newUser = createGeneratedUser(username, encodingPassword, email);
        if(newUser == null) {throw new RuntimeException("User with email " + email + " already exists");}
        return new SignUpResponse(username, new Date());
    }

    public JwtTokens signIn(String email, String password) {
        // 1. email. password 확인.
        // 2. security context에 유저 정보 추가.
        // 3. response에 쿠키 추가.
        User user = userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User with email not found"));

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user.getUsername(), password);

        try{
            Authentication authentication = authenticationManagerBuilder.getObject().authenticate(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            String access = jwtProvider.createToken(authentication, TokenType.ACCESS_TOKEN);
            String refresh = jwtProvider.createToken(authentication, TokenType.REFRESH_TOKEN);
            ResponseCookie refreshCookie = jwtProvider.createRefreshCookie(refresh, user.getId());
            return new JwtTokens(access, refreshCookie);
        }
        catch(Exception e){
            log.error("Authentication failed: ", e);
            throw new RuntimeException("Authentication failed");
        }
    }

    private User createGeneratedUser(String username, String password, String email) {
        UserCredentional userCredentional = new UserCredentional(password);
        User user = new User(username, email, Role.getRoles("USER"), userCredentional);
        userCredentional.setUser(user);
        return userRepository.save(user);
    }
}
