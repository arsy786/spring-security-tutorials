package dev.arsalaan.springsecurityjwt.controller;

import dev.arsalaan.springsecurityjwt.dto.AuthRequest;
import dev.arsalaan.springsecurityjwt.dto.AuthResponse;
//import dev.arsalaan.springsecurityjwt.entity.Role;
import dev.arsalaan.springsecurityjwt.entity.User;
//import dev.arsalaan.springsecurityjwt.repository.RoleRepository;
import dev.arsalaan.springsecurityjwt.repository.UserRepository;
import dev.arsalaan.springsecurityjwt.security.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private PasswordEncoder passwordEncoder;

//    @Autowired
//    private RoleRepository roleRepository;

    @PostMapping("/login") // should use a loginDto instead for consistency
    public ResponseEntity<?> authenticateUser(@RequestBody AuthRequest authRequest){

        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getEmail(), authRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);

//        User user = (User) authentication.getPrincipal();

        // get token form jwtTokenUtil
        String accessToken = jwtTokenUtil.generateToken(authentication);
        AuthResponse authResponse = new AuthResponse(authRequest.getEmail(), accessToken);

        return ResponseEntity.ok().body(authResponse);
    }

    @PostMapping("/register") // should use a registerDto instead of handling user entity
    public ResponseEntity<?> registerUser(@RequestBody User registerUser){

        // add check for email exists in DB
        if(userRepository.findByEmail(registerUser.getEmail()).isPresent()){
            return new ResponseEntity<>("Email is already taken!", HttpStatus.BAD_REQUEST);
        }

        // create and save new user object
        User saveUser = new User();
        saveUser.setEmail(registerUser.getEmail());
        saveUser.setPassword(passwordEncoder.encode(registerUser.getPassword()));

//        Role roles = roleRepository.findByName("ROLE_ADMIN").get();
//        user.setRoles(Collections.singleton(roles));

        saveUser.setRoles("ROLE_USER");

        userRepository.save(saveUser);

        return new ResponseEntity<>("User registered successfully", HttpStatus.OK);

    }


}
