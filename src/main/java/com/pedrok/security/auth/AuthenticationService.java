package com.pedrok.security.auth;

import com.pedrok.security.auth.request.*;
import com.pedrok.security.auth.response.AuthenticationResponse;
import com.pedrok.security.config.JwtService;
import com.pedrok.security.email.EmailService;
import com.pedrok.security.tokenBlacklist.TokenBlacklisted;
import com.pedrok.security.tokenBlacklist.TokenBlacklistedRepository;
import com.pedrok.security.user.Role;
import com.pedrok.security.user.User;
import com.pedrok.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
    private final EmailService emailService;
    @Value("${application.url.base}")
    private String baseUrl;

    public ResponseEntity<?> register(RegisterRequest request) {
        if (repository.existsByEmail(request.getEmail())) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Usuario já cadastrado com esse email!");
        }

        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .enabled(false)
                .build();
        User savedUser = repository.save(user);
        String jwtToken = jwtService.generateToken(savedUser);

        //String baseUrl = "localhost:8080"; // transformar em propertie
        String confirmationUrl = baseUrl + "/v1/auth/confirm-email?token=" + jwtToken;
        emailService.send(user.getEmail(),
                "CONFIRMAR CADASTRO",
                "Bem vindo, confirme seu cadastro: " + confirmationUrl);

        return ResponseEntity.status(HttpStatus.CREATED).body("Verifique seu email para continuar o cadastro :)");
    }

    public AuthenticationResponse confirmEmail(ConfirmEmailRequest request) {
        String tokenValue = request.getToken();

        String username = jwtService.extractUsername(tokenValue);
        User user = repository.findByEmail(username)
                .orElseThrow();

        user.setEnabled(true);

        repository.save(user);

        return AuthenticationResponse.builder()
                .token(tokenValue)
                .build();
    }

    public ResponseEntity<?> changePassword(ChangePasswordRequest request) {
        if (!repository.existsByEmail(request.getEmail())) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("nenhum cadastro com esse email!");
        }

        User user = repository.findByEmail(request.getEmail())
                .orElseThrow();

        if (!user.isEnabled()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body("usuario inativo!");
        }

        String jwtToken = jwtService.generateToken(user);

        String confirmationUrl = baseUrl + "/v1/auth/change-password-confirmation?token=" + jwtToken;

        emailService.send(user.getEmail(),
                "MUDAR SENHA",
                "Olá, mude sua senha: " + confirmationUrl);

        return ResponseEntity.ok("Verifique seu email para continuar com a mudança de senha");
    }

    public Boolean changePasswordConfirmation
            (ConfirmEmailRequest confirmEmailRequest
            , ChangePasswordConfirmationRequest changePasswordConfirmationRequest) {
        String tokenValue = confirmEmailRequest.getToken();

        String username = jwtService.extractUsername(tokenValue);
        User user = repository.findByEmail(username)
                .orElseThrow();

        user.setPassword(passwordEncoder.encode(changePasswordConfirmationRequest.getPassword()));
        repository.save(user);
        return true;
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

        if (!tokenBlacklistedRepository.existsByTokenValue(tokenValue)) {
            TokenBlacklisted tokenBlacklisted = TokenBlacklisted.builder()
                    .tokenValue(tokenValue)
                    .build();
            tokenBlacklistedRepository.save(tokenBlacklisted);
            return true;
        }
        return false;
    }
}
