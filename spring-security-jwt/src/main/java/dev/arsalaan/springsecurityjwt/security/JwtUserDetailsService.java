package dev.arsalaan.springsecurityjwt.security;

//import dev.arsalaan.springsecurityjwt.entity.Role;
import dev.arsalaan.springsecurityjwt.entity.User;
import dev.arsalaan.springsecurityjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class JwtUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override // email used instead of username
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));

//        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), mapRolesToAuthorities(user.getRoles()));
        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), getAuthorities(user));
    }

//    private Collection< ? extends GrantedAuthority> mapRolesToAuthorities(Set<Role> roles) {
//        return roles.stream().map(role -> new SimpleGrantedAuthority(role.getName())).collect(Collectors.toList());
//    }

    public Collection<? extends GrantedAuthority> getAuthorities(User user) {
        return Arrays.stream(user
                        .getRoles()
                        .split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

}
