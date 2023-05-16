package com.pedrok.security.auth;

import com.pedrok.security.auth.request.AuthenticationRequest;
import com.pedrok.security.auth.request.LogoutRequest;
import com.pedrok.security.auth.request.RegisterRequest;
import com.pedrok.security.auth.response.AuthenticationResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(service.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(service.authenticate(request));
    }

    @RequestMapping("/logout")
    public ResponseEntity<Boolean> logout(@RequestBody LogoutRequest request) {
        return ResponseEntity.ok(service.logout(request));
    }
}
