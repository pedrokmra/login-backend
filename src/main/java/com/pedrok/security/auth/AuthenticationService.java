package com.pedrok.security.auth;

import com.pedrok.security.auth.request.AuthenticationRequest;
import com.pedrok.security.auth.request.LogoutRequest;
import com.pedrok.security.auth.request.RegisterRequest;
import com.pedrok.security.auth.response.AuthenticationResponse;
import com.pedrok.security.config.JwtService;
import com.pedrok.security.tokenBlacklist.TokenBlacklisted;
import com.pedrok.security.tokenBlacklist.TokenBlacklistedRepository;
import com.pedrok.security.user.Role;
import com.pedrok.security.user.User;
import com.pedrok.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;
    private final TokenBlacklistedRepository tokenBlacklistedRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        User savedUser = repository.save(user);

        String jwtToken = jwtService.generateToken(savedUser);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    request.getEmail(),
                    request.getPassword()
                )
        );

        User user = repository.findByEmail(request.getEmail())
                .orElseThrow();

        String jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public Boolean logout(LogoutRequest request) {
        String tokenValue = request.getToken();

        if (tokenBlacklistedRepository.existsByTokenValue(tokenValue)) {
            TokenBlacklisted tokenBlacklisted = TokenBlacklisted.builder()
                    .tokenValue(tokenValue)
                    .build();
            tokenBlacklistedRepository.save(tokenBlacklisted);
            return true;
        }
        return false;
    }
}
