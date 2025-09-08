package com.example.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

@Component
@Getter
public class JwtUtils {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.access-token-expiration-ms}")
    private long accessTokenExpirationMs;

    private Algorithm algorithm;
    private JWTVerifier verifier;

    @PostConstruct
    public void init() {
        if (jwtSecret == null || jwtSecret.isBlank() || jwtSecret.equals("change_me_to_a_strong_secret")) {
            System.err.println("[JWT] Warning: using default/weak JWT secret — override via env JWT_SECRET");
        }
        algorithm = Algorithm.HMAC256(jwtSecret.getBytes(StandardCharsets.UTF_8));
        verifier = JWT.require(algorithm).build();
    }

    public String generateAccessToken(UserDetails userDetails) {
        Date now = new Date();
        Date expire = new Date(now.getTime() + accessTokenExpirationMs);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(Object::toString)
                .toList();

        return JWT.create()
                .withSubject(userDetails.getUsername())
                .withIssuedAt(now)
                .withExpiresAt(expire)
                .withClaim("roles", roles)
                .sign(algorithm);
    }

    public String getUsernameFromToken(String token) {
        DecodedJWT decoded = verifier.verify(token);
        return decoded.getSubject();
    }

    public boolean validateToken(String token) {
        try {
            verifier.verify(token);
            return true;
        } catch (JWTVerificationException ex) {
            return false;
        }
    }
}
