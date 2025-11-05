package com.docker.jwt.Security;

import com.docker.jwt.Service.RedisService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;

@RequiredArgsConstructor
@Component
public class JWTFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;
    private final RedisService redisService;

    private static final String[] WHITE_LIST = {
            "/api/v1/user/signUp",
            "/api/v1/user/signIn",
            "/swagger-ui/**",
            "/v3/api-docs/**"
    };
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
    throws ServletException, IOException {
        //1. 인증이 필요한 도메인인지 확인
        //2. access 토큰 서명값, 유효시간 체크
        //3. 되면 시큐리티에 유저 정보 추가하고 안되면 refresh 토큰 꺼내서 체크
        //4. 되면 access 토큰 다시 재발급하고 시큐리티에 유저 정보 추가.
        //5. 되면 access 토큰 다시 재발급하고 시큐리티에 유저 정보 추가.

        String path = request.getRequestURI();
        System.out.println(">>> URI: " + request.getRequestURI());
        boolean isWhite = Arrays.stream(WHITE_LIST)
                .anyMatch(pattern -> pathMatcher.match(pattern, path));

            if (isWhite) {
                filterChain.doFilter(request, response); return;
            }
            String accessToken = jwtProvider.resolveToken(request);

            if (accessToken != null && jwtProvider.validateToken(accessToken))
                filterChain.doFilter(request, response);
            else {
                Cookie[] cookies = request.getCookies();
                if (cookies == null) throw new RuntimeException("Cookies are not allowed");
                Cookie refreshToken = Arrays.stream(cookies)
                        .filter(c -> c.getName().equals("refresh_token"))
                        .findFirst()
                        .orElse(null);
                if (refreshToken == null || !jwtProvider.validateToken(refreshToken.getValue())) {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED); return;
                }

                Claims payload = jwtProvider.getPayload(refreshToken.getValue());
                String redisToken = redisService.getValue(payload.getSubject());
                if (redisToken == null || !redisToken.equals(refreshToken.getValue())) {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED); return;
                }

                String newToken = jwtProvider.createToken(Long.parseLong(
                        payload.getSubject()), payload.get("roles", String.class), TokenType.ACCESS_TOKEN);
                response.addHeader("Authorization", "Bearer " + newToken);
                Authentication auth = jwtProvider.getAuthentication(newToken);
                SecurityContextHolder.getContext().setAuthentication(auth);
                filterChain.doFilter(request, response);
            }
    }
}
