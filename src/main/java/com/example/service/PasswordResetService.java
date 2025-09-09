package com.example.service;

import com.example.entity.PasswordResetToken;
import com.example.entity.User;
import com.example.repository.PasswordResetTokenRepository;
import com.example.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

@Service
@RequiredArgsConstructor
@Transactional
public class PasswordResetService {

    private final PasswordResetTokenRepository tokenRepository;
    private final UserRepository userRepository;

    @Value("${auth.password-reset-expiration-minutes:30}")
    private long expiryMinutes;

    public String createTokenForEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User with email not found"));

        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        PasswordResetToken prt = PasswordResetToken.builder()
                .token(token)
                .user(user)
                .expiry(Instant.now().plusSeconds(expiryMinutes * 60))
                .build();
        tokenRepository.save(prt);

        return token;
    }

    public User validateTokenAndGetUser(String token) {
        PasswordResetToken prt = tokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid password reset token"));
        if (prt.getExpiry().isBefore(Instant.now())) {
            tokenRepository.delete(prt);
            throw new RuntimeException("Token expired");
        }
        return prt.getUser();
    }

    public void removeTokensForUser(User user) {
        tokenRepository.deleteByUserId(user.getId());
    }
}
