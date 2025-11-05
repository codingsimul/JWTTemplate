package com.docker.jwt.Security;

import com.docker.jwt.Service.RedisService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtProvider {

    @Value("${jwt.secrets}")
    private String secretKey;
    private SecretKey key;
    private Long accessValidityTime = 3 * 60 * 1000L;
    private Long refreshValidityTime = 6 * 60 * 1000L;

    private final RedisService redisService;

    @PostConstruct
    public void init() {
        key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    public String createToken(Authentication authentication, TokenType tokenType) {
        // 1. 토큰에 필요한 권한, 그외 사용자 정보 담기(name)
        // 2. 현재 기준 유효 기간 설정.
        // 3. access token과 refresh token 생성 + 서명키로 암호화하여
        String authorities = authentication.getAuthorities().stream()
                .map((authority)-> authority.getAuthority())
                .collect(Collectors.joining(","));

        long now = new Date().getTime();

        UserDetailsServiceUser userDetailsServiceUser = (UserDetailsServiceUser) authentication.getPrincipal();

        String token = Jwts.builder()
                .setHeaderParam("typ", tokenType.name())
                .signWith(SignatureAlgorithm.HS256 ,key)
                .setSubject(String.valueOf(userDetailsServiceUser.getId()))
                .claim("roles", authorities)
                .setExpiration(tokenType == TokenType.ACCESS_TOKEN
                        ? new Date(now + accessValidityTime) : new Date(now + refreshValidityTime))
                .compact();
        return token;
    }

    public String createToken(Long userId, String roles, TokenType tokenType) {
        long now = new Date().getTime();

        String token = Jwts.builder()
                .setHeaderParam("typ", tokenType.name())
                .signWith(SignatureAlgorithm.HS256, key)
                .setSubject(String.valueOf(userId))
                .claim("roles", roles)
                .setExpiration(tokenType == TokenType.ACCESS_TOKEN
                        ? new Date(now + accessValidityTime)
                        : new Date(now + refreshValidityTime))
                .compact();

        return token;
    }

    public String resolveToken(HttpServletRequest request){
        String bearerToken = request.getHeader("Authorization");
        if(bearerToken != null && bearerToken.startsWith("Bearer "))return request.getHeader("Authorization").substring(7);
        else return null;
    }
    public boolean validateToken(String token){
        try{
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        }catch (ExpiredJwtException e){
            log.error("Token expired");
            return false;
        }
        catch(SecurityException e){
            log.error("Invalid token");
            return false;
        }
        catch(Exception e){
            log.error("error Token: "+e.getMessage());
            return false;
        }
    }

    public Claims getPayload(String token){
        try{
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
        }
        catch (Exception e){
            log.error("error Token: "+e.getMessage());
            throw new RuntimeException("Invalid token");
        }
    }

    public ResponseCookie createRefreshCookie(String refreshToken, Long userId) {
        ResponseCookie rc = ResponseCookie
                .from("refresh_token",refreshToken)
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .maxAge(60 * 60 * 24)
                .path("/")
                .build();
        redisService.setValue(String.valueOf(userId), refreshToken);
        return rc;
    }

    public Authentication getAuthentication(String token){
        try{
            Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
            String id = claims.getSubject();
            List<SimpleGrantedAuthority> authorities
                    = Arrays.stream(claims.get("roles").toString().split(","))
                    .map(r -> new SimpleGrantedAuthority(r)).collect(Collectors.toList());

            return new UsernamePasswordAuthenticationToken(id, null, authorities);

        }catch (Exception e){log.error(e.getMessage()); throw new RuntimeException("Invalid token");}
    }

}
