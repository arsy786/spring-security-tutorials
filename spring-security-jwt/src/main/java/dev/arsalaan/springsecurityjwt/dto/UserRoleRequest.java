package dev.arsalaan.springsecurityjwt.dto;

import lombok.Data;

@Data
public class UserRoleRequest {
    private String email;
    private String roleName;
}
