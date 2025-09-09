package com.example.controller;

import com.example.dto.*;
import com.example.entity.RefreshToken;
import com.example.entity.User;
import com.example.service.PasswordResetService;
import com.example.service.RefreshTokenService;
import com.example.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AccountController {

    private final UserService userService;
    private final RefreshTokenService refreshTokenService;
    private final PasswordResetService passwordResetService;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(@Valid @RequestBody ChangePasswordDto dto, Authentication auth) {
        String username = auth.getName();
        User user = userService.findByEmail(username).orElseThrow(() -> new RuntimeException("User not found"));
        if (!passwordEncoder.matches(dto.getOldPassword(), user.getPassword())) {
            return ResponseEntity.badRequest().body(Map.of("error", "Old password is incorrect"));
        }
        user.setPassword(passwordEncoder.encode(dto.getNewPassword()));
        userService.save(user);
        refreshTokenService.deleteByUser(user);
        return ResponseEntity.ok(Map.of("status", "password changed"));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordDto dto) {
        String token = passwordResetService.createTokenForEmail(dto.getEmail());
        return ResponseEntity.ok(Map.of("resetToken", token));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordDto dto) {
        User user = passwordResetService.validateTokenAndGetUser(dto.getToken());
        user.setPassword(passwordEncoder.encode(dto.getNewPassword()));
        userService.save(user);
        passwordResetService.removeTokensForUser(user);
        refreshTokenService.deleteByUser(user);
        return ResponseEntity.ok(Map.of("status", "password reset"));
    }

    @GetMapping("/sessions")
    public ResponseEntity<?> sessions(Authentication auth) {
        String username = auth.getName();
        User user = userService.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        List<Map<String, Object>> sessions = refreshTokenService.findAllByUser(user).stream()
                .map(rt -> {
                    Map<String, Object> m = new HashMap<>();
                    m.put("id", rt.getId());
                    String preview = null;
                    if (rt.getToken() != null) {
                        int len = Math.min(8, rt.getToken().length());
                        preview = rt.getToken().substring(0, len) + "...";
                    }
                    m.put("tokenPreview", preview);
                    m.put("expiry", rt.getExpiry());
                    m.put("deviceInfo", rt.getDeviceInfo() == null ? "unknown" : rt.getDeviceInfo());
                    return m;
                })
                .collect(Collectors.toList());

        return ResponseEntity.ok(sessions);
    }

    @PostMapping("/revoke")
    public ResponseEntity<?> revoke(@Valid @RequestBody RevokeDto dto, Authentication auth) {
        String username = auth.getName();
        User user = userService.findByEmail(username).orElseThrow(() -> new RuntimeException("User not found"));
        return refreshTokenService.findByToken(dto.getRefreshToken())
                .map(rt -> {
                    if (!rt.getUser().getId().equals(user.getId())) {
                        return ResponseEntity.status(403).body(Map.of("error", "Not allowed"));
                    }
                    refreshTokenService.deleteByUser(rt.getUser());
                    return ResponseEntity.ok(Map.of("status", "revoked"));
                })
                .orElseGet(() -> ResponseEntity.badRequest().body(Map.of("error", "Token not found")));
    }
}
