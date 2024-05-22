package com.example.clase7gtics.repository;

import com.example.clase7gtics.entity.Category;
import com.example.clase7gtics.entity.Product;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ProductRepository extends JpaRepository<Product, Integer>{

    public List<Product> findByCategory(Category category);
}

