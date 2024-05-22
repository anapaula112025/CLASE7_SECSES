package com.example.clase7gtics.repository;

import com.example.clase7gtics.entity.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UsuarioRepository extends JpaRepository<Usuario, Integer> {
    //para buscar por email, debido a que el usuario logueado es identificado en Spring Security por el email
    public Usuario findByEmail(String email);

}


