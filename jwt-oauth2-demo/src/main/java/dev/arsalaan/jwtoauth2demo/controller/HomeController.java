package dev.arsalaan.jwtoauth2demo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class HomeController {

    @GetMapping("/starter")
    public String starter() {
        return "Welcome to the starter page";
    }

    @GetMapping("/home")
//    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')") roles feature not incorporated yet
    public String home(Principal principal) {
        return "Hello, " + principal.getName();
    }

    @PreAuthorize("hasAuthority('SCOPE_read')")
//    @PreAuthorize("hasRole('ROLE_ADMIN')") roles feature not incorporated yet
    @GetMapping("/secure")
    public String secure() {
        return "This is secured!";
    }


}
