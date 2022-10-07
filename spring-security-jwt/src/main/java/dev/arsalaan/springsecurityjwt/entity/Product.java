package dev.arsalaan.springsecurityjwt.entity;

import lombok.*;
import javax.persistence.*;


@Getter // Defines the getter methods of the member fields
@Setter // Defines the setter methods of the member fields
@ToString // Defines a meaningful toString implementation of this class
@AllArgsConstructor // Defines all arguments constructor
@NoArgsConstructor // Defines the default constructor
@Entity // Marks this class as an entity
@Table(name = "products") // Can change entity name in table
public class Product {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "price", nullable = false)
    private float price;

}
