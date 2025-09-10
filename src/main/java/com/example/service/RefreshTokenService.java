package com.example.service;

import com.example.dto.RefreshCreateResult;
import com.example.entity.RefreshToken;
import com.example.entity.User;
import com.example.repository.RefreshTokenRepository;
import com.example.security.TokenHash;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional
@Getter
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${jwt.refresh-token-expiration-ms}")
    private long refreshTokenDurationMs;

    public RefreshCreateResult createRefreshToken(User user, String deviceInfo) {
        String raw = UUID.randomUUID().toString();
        String hash = TokenHash.sha256Hex(raw);

        RefreshToken token = RefreshToken.builder()
                .user(user)
                .tokenHash(hash)
                .expiry(Instant.now().plusMillis(refreshTokenDurationMs))
                .deviceInfo(deviceInfo)
                .build();

        RefreshToken saved = refreshTokenRepository.save(token);
        return new RefreshCreateResult(saved, raw);
    }

    public Optional<RefreshToken> findByTokenRaw(String raw) {
        String hash = TokenHash.sha256Hex(raw);
        return refreshTokenRepository.findByTokenHash(hash);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiry().isBefore(Instant.now())) {
            refreshTokenRepository.delete(token);
            throw new RuntimeException("Refresh token was expired. Please sign in again.");
        }
        return token;
    }

    public int deleteByUser(User user) {
        return refreshTokenRepository.deleteByUser(user);
    }

    public List<RefreshToken> findAllByUser(User user) {
        return refreshTokenRepository.findAllByUser(user);
    }

    public void deleteByTokenHash(String tokenHash) {
        refreshTokenRepository.deleteByTokenHash(tokenHash);
    }

    public RefreshCreateResult rotateRefreshToken(String rawToken) {
        String hash = TokenHash.sha256Hex(rawToken);
        RefreshToken existing = refreshTokenRepository.findByTokenHash(hash)
                .orElseThrow(() -> new RuntimeException("Refresh token not found"));

        verifyExpiration(existing);

        User user = existing.getUser();
        String deviceInfo = existing.getDeviceInfo();

        refreshTokenRepository.delete(existing);

        return createRefreshToken(user, deviceInfo);
    }
}
