package dev.arsalaan.springsecurityjwt.repository;

import dev.arsalaan.springsecurityjwt.entity.Product;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ProductRepository extends JpaRepository<Product, Long> {
}
