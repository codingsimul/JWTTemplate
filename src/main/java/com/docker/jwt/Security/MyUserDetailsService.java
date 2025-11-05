package com.docker.jwt.security;
import com.docker.jwt.Domain.User;
import com.docker.jwt.Repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class MyUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(
                () -> new RuntimeException("Username not found"));

        List<GrantedAuthority> grantedAuthorities = Arrays.stream(Role.getRoles(user.getRoles()).split(","))
                .map((r)-> new SimpleGrantedAuthority(r)).collect(Collectors.toList());
        // User 객체는 권한 정보가 있어야 된다.
        return new UserDetailsServiceUser(user.getUsername(), user.getPassword(),
                grantedAuthorities);
        // Authentication 객체와 비교할 대상.
    }
}