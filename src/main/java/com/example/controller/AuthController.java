package com.example.controller;

import com.example.dto.*;
import com.example.entity.RefreshToken;
import com.example.entity.Role;
import com.example.entity.User;
import com.example.security.JwtUtils;
import com.example.service.RefreshTokenService;
import com.example.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final AuthenticationManager authManager;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequestDto req) {
        User user = userService.register(req.getUsername(), req.getEmail(), req.getPassword());
        return ResponseEntity.ok(Map.of("id", user.getId(), "email", user.getEmail()));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequestDto req, HttpServletResponse response) {
        try {
            Authentication authentication = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(req.getUsernameOrEmail(), req.getPassword())
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String accessToken = jwtUtils.generateAccessToken(userDetails);

            User user = userService.findByEmail(userDetails.getUsername())
                    .orElseThrow(() -> new RuntimeException("User entity not found after authentication"));

            // create refresh token (raw + hashed saved)
            String userAgent = ""; // if request available, pass header; else empty
            // if you have HttpServletRequest available, use request.getHeader("User-Agent")
            RefreshCreateResult res = refreshTokenService.createRefreshToken(user, userAgent);

            // set HttpOnly cookie with raw token
            Cookie cookie = new Cookie(REFRESH_COOKIE_NAME, res.getRawToken());
            cookie.setHttpOnly(true);
            cookie.setSecure(false); // set true in production (HTTPS)
            cookie.setPath("/");
            cookie.setMaxAge((int) (refreshTokenService.getRefreshTokenDurationMs() / 1000));
            response.addCookie(cookie);

            return ResponseEntity.ok(Map.of("accessToken", accessToken));
        } catch (AuthenticationException ex) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody(required = false) RefreshRequestDto body,
                                     HttpServletRequest request,
                                     HttpServletResponse response) {
        // 1. try cookie
        String raw = null;
        if (request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                if (REFRESH_COOKIE_NAME.equals(c.getName())) {
                    raw = c.getValue();
                }
            }
        }

        if (raw == null && body != null) {
            raw = body.getRefreshToken();
        }
        if (raw == null) {
            return ResponseEntity.status(400).body(Map.of("error", "No refresh token provided"));
        }

        try {
            RefreshCreateResult newToken = refreshTokenService.rotateRefreshToken(raw);
            User user = newToken.getRefreshTokenEntity().getUser();
            UserDetails ud = userService.loadUserByUsername(user.getEmail());
            String newAccess = jwtUtils.generateAccessToken(ud);

            Cookie cookie = new Cookie(REFRESH_COOKIE_NAME, newToken.getRawToken());
            cookie.setHttpOnly(true);
            cookie.setSecure(false); // true in prod
            cookie.setPath("/");
            cookie.setMaxAge((int) (refreshTokenService.getRefreshTokenDurationMs() / 1000));
            response.addCookie(cookie);

            return ResponseEntity.ok(Map.of("accessToken", newAccess));
        } catch (RuntimeException ex) {
            return ResponseEntity.status(403).body(Map.of("error", ex.getMessage()));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@Valid @RequestBody RefreshRequestDto req) {
        String token = req.getRefreshToken();
        return refreshTokenService.findByToken(token)
                .map(rt -> {
                    refreshTokenService.deleteByUser(rt.getUser());
                    return ResponseEntity.ok(Map.of("status", "logged out"));
                })
                .orElseGet(() -> ResponseEntity.badRequest().body(Map.of("error", "Refresh token not found")));
    }

    @GetMapping("/me")
    public ResponseEntity<?> me() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return ResponseEntity.status(401).body(Map.of("error", "Unauthenticated"));
        }

        String username = auth.getName();
        return userService.findByEmail(username)
                .map(u -> ResponseEntity.ok(Map.of(
                        "id", u.getId(),
                        "username", u.getUsername(),
                        "email", u.getEmail(),
                        "roles", u.getRoles().stream().map(Role::getName).toList()
                )))
                .orElseGet(() -> ResponseEntity.status(404).body(Map.of("error", "User not found")));
    }
}