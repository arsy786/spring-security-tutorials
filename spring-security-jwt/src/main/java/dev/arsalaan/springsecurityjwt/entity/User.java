package dev.arsalaan.springsecurityjwt.entity;

import lombok.*;

import javax.persistence.*;
import javax.validation.constraints.Email;
import java.util.Set;

@Data
@Entity
@Table(name = "users") // user is a reserved keyword therefore must rename to users
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(nullable = false, unique = true)
    @Email
    private String email;

    @Column(nullable = false)
    private String password;

    private String roles; // can use entity or field for roles

//    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
//    @JoinTable(name = "user_roles",
//            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"),
//            inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id"))
//    private Set<Role> roles;

}
