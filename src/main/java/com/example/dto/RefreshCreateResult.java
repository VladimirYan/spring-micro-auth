package com.example.dto;

import com.example.entity.RefreshToken;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class RefreshCreateResult {
    private RefreshToken refreshTokenEntity;
    private String rawToken;
}
