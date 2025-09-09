package com.example.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class RevokeDto {
    @NotBlank
    private String refreshToken;
}
