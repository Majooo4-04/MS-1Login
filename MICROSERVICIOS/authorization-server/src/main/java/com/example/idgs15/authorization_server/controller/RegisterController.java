// package com.example.idgs15.authorization_server.controller;

// import com.example.idgs15.authorization_server.dto.RegisterRequest;
// import com.example.idgs15.authorization_server.entity.Users;
// import com.example.idgs15.authorization_server.repository.UserRepository;
// import lombok.RequiredArgsConstructor;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.access.prepost.PreAuthorize;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.web.bind.annotation.*;

// @RestController
// @RequiredArgsConstructor
// public class RegisterController {

//     private final UserRepository userRepository;
//     private final PasswordEncoder passwordEncoder;

//     @PreAuthorize("hasRole('ADMIN')")
//     @PostMapping("/register")
//     public ResponseEntity<?> register(@RequestBody RegisterRequest request) {

//         if (userRepository.existsByUsername(request.getUsername())) {
//             return ResponseEntity.badRequest().body("El nombre de usuario ya existe");
//         }

//         if (userRepository.existsByCorreo(request.getCorreo())) {
//             return ResponseEntity.badRequest().body("El correo ya está registrado");
//         }

//         if (!"USER".equals(request.getRole()) && !"ADMIN".equals(request.getRole())) {
//             return ResponseEntity.badRequest().body("Rol inválido, debe ser USER o ADMIN");
//         }

//         Users user = new Users();
//         user.setNombre(request.getNombre());
//         user.setTelefono(request.getTelefono());
//         user.setCorreo(request.getCorreo());
//         user.setUsername(request.getUsername());
//         user.setPassword(passwordEncoder.encode(request.getPassword()));
//         user.setRole(request.getRole());

//         userRepository.save(user);

//         return ResponseEntity.ok("Usuario registrado correctamente");
//     }
// }
package com.example.idgs15.authorization_server.controller;

import com.example.idgs15.authorization_server.dto.RegisterRequest;
import com.example.idgs15.authorization_server.entity.Users;
import com.example.idgs15.authorization_server.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class RegisterController {

    private static final List<String> ROLES_VALIDOS = List.of("ADMIN", "SERVICIO", "VENTAS", "MARKETING");

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @PreAuthorize("hasAnyRole('ADMIN','SERVICIO','VENTAS','MARKETING')")
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest request) {
        try {
            if (request.getUsername() == null || request.getUsername().isBlank()) {
                return ResponseEntity.badRequest().body("El nombre de usuario es obligatorio");
            }

            if (userRepository.existsByUsername(request.getUsername())) {
                return ResponseEntity.badRequest().body("El nombre de usuario ya existe");
            }

            if (userRepository.existsByCorreo(request.getCorreo())) {
                return ResponseEntity.badRequest().body("El correo ya está registrado");
            }

            if (request.getRole() == null || !ROLES_VALIDOS.contains(request.getRole())) {
                return ResponseEntity.badRequest().body("Rol inválido. Debe ser: " + ROLES_VALIDOS);
            }

            Users user = new Users();
            user.setNombre(request.getNombre());
            user.setTelefono(request.getTelefono());
            user.setCorreo(request.getCorreo());
            user.setUsername(request.getUsername());
            user.setPassword(passwordEncoder.encode(request.getPassword()));
            user.setRole(request.getRole());

            userRepository.save(user);

            return ResponseEntity.ok("Usuario registrado correctamente");

        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al registrar usuario: " + ex.getMessage());
        }
    }
}