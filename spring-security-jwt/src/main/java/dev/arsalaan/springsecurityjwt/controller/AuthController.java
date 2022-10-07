package dev.arsalaan.springsecurityjwt.controller;

import dev.arsalaan.springsecurityjwt.dto.JwtRequest;
import dev.arsalaan.springsecurityjwt.dto.JwtResponse;
import dev.arsalaan.springsecurityjwt.dto.UserRoleRequest;
import dev.arsalaan.springsecurityjwt.entity.Role;
import dev.arsalaan.springsecurityjwt.entity.User;
import dev.arsalaan.springsecurityjwt.repository.RoleRepository;
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
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.Collections;
import java.util.List;

// NOTE: Controller layer should only interact with Service layer, which in turn should contain business logic and interact with Repository layer.
// But, for demonstration purposes, Repository layer exposed directly to Controller.
// NOTE: Controller layer should consume (via endpoint) and respond (via service) with DTO's only.
// But, for demonstration purposes, Controller layer interacts with entities at times here.

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @GetMapping("/users")
    public ResponseEntity<List<User>>getUsers() {
        return ResponseEntity.ok().body(userRepository.findAll());
    }

    @PostMapping("/user/save")
    public ResponseEntity<User>saveUser(@RequestBody User user) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/auth/user/save").toUriString());
        return ResponseEntity.created(uri).body(userRepository.save(user));
    }

    @PostMapping("/role/save")
    public ResponseEntity<Role>saveRole(@RequestBody Role role) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
        return ResponseEntity.created(uri).body(roleRepository.save(role));
    }

    @PostMapping("/role/addtouser")
    public ResponseEntity<?>addRoleToUser(@RequestBody UserRoleRequest addRoleToUserRequest) {
        User user = userRepository.findByEmail(addRoleToUserRequest.getEmail()).get();
        Role role = roleRepository.findByName(addRoleToUserRequest.getRoleName()).get();
        user.getRoles().add(role);
        userRepository.save(user);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody JwtRequest jwtRequest){

        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(jwtRequest.getEmail(), jwtRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // get token form jwtTokenUtil
        String accessToken = jwtTokenUtil.generateToken(authentication);
        JwtResponse jwtResponse = new JwtResponse(jwtRequest.getEmail(), accessToken);

        return ResponseEntity.ok().body(jwtResponse);
    }

    @PostMapping("/register") // should use a registerDto instead of handling User entity in Controller layer
    public ResponseEntity<?> registerUser(@RequestBody User registerUser){

        // add check for email exists in DB
        if(userRepository.findByEmail(registerUser.getEmail()).isPresent()){
            return new ResponseEntity<>("Email is already taken!", HttpStatus.BAD_REQUEST);
        }

        // create and save new user object
        User saveUser = new User();
        saveUser.setEmail(registerUser.getEmail());
        saveUser.setPassword(passwordEncoder.encode(registerUser.getPassword()));

        // every new registered user has ROLE_USER by default
        Role roles = roleRepository.findByName("ROLE_USER").get();
        saveUser.setRoles(Collections.singleton(roles));

        userRepository.save(saveUser);

        return new ResponseEntity<>("User registered successfully", HttpStatus.OK);
    }


}
