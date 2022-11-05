package dev.arsalaan.jwtoauth2demo.dto;

import lombok.Data;

@Data
public class JwtLoginRequest {
    private String username;
    private String password;
}
