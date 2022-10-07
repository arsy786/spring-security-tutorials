package dev.arsalaan.springsecurityjwt.controller;

import dev.arsalaan.springsecurityjwt.entity.Product;
import dev.arsalaan.springsecurityjwt.repository.ProductRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.net.URI;
import java.util.List;

// NOTE: Controller layer should only interact with Service layer, which in turn should contain business logic and interact with Repository layer.
// But, for demonstration purposes, Repository layer exposed directly to Controller.
// NOTE: Controller layer should consume (via endpoint) and respond (via service) with DTO's only.
// But, for demonstration purposes, Controller layer interacts with entities at times here.

@RestController
@RequestMapping("/products")
public class ProductController {

    private ProductRepository productRepository;

    public ProductController(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    public List<Product> getAllProducts() {
        return productRepository.findAll();
    }

    @PostMapping
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<Product> createProduct(@RequestBody @Valid Product product) {
        Product savedProduct = productRepository.save(product);
        URI productURI = URI.create("/products/" + savedProduct.getId());
        return ResponseEntity.created(productURI).body(savedProduct);
    }

}
