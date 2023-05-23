package com.pedrok.security.auth;

import com.pedrok.security.auth.request.*;
import com.pedrok.security.auth.response.AuthenticationResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService service;

    @PostMapping("register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        return service.register(request);
    }

    @GetMapping("confirm-email")
    public ResponseEntity<AuthenticationResponse> confirmEMail(@RequestParam("token") ConfirmEmailRequest confirmEmailRequest) {
        return ResponseEntity.ok(service.confirmEmail(confirmEmailRequest));
    }

    @PostMapping("change-password")
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest request) {
        return ResponseEntity.ok(service.changePassword(request));
    }

    @PostMapping("change-password-confirmation")
    public ResponseEntity<Boolean> changePasswordConfirmation
            (@RequestParam("token") ConfirmEmailRequest confirmEmailRequest,
            @RequestBody ChangePasswordConfirmationRequest changePasswordConfirmationRequest) {
        return ResponseEntity.ok(service.changePasswordConfirmation(confirmEmailRequest, changePasswordConfirmationRequest));
    }

    @PostMapping("authenticate")
    public ResponseEntity<?> authenticate(@RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(service.authenticate(request));
    }

    @RequestMapping("logout")
    public ResponseEntity<Boolean> logout(@RequestBody LogoutRequest request) {
        return ResponseEntity.ok(service.logout(request));
    }
}
