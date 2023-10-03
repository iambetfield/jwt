package com.example.demojwt.service;

import com.example.demojwt.auth.AuthReponse;
import com.example.demojwt.auth.LoginRequest;
import com.example.demojwt.auth.RegisterRequest;
import com.example.demojwt.entities.Role;
import com.example.demojwt.entities.User;
import com.example.demojwt.jwt.JwtService;
import com.example.demojwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    public AuthReponse login(LoginRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(),request.getPassword()));
        UserDetails user = userRepository.findByUsername(request.getUsername()).orElseThrow();
        String token = jwtService.getToken(user);

        return AuthReponse.builder()
                .token(token)
                .build();

    }

    public AuthReponse register(RegisterRequest request) {
        User user = User.builder()
                .username(request.getUsername())
                //.password(request.getPassword()) //guardamos la contraseña ya encriptada!!, no asi
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .lastName(request.getLastName())
                .firstName(request.getFirstName())
                .country(request.getCountry())
                .build();
        //guardamos el usuario en la DB
        userRepository.save(user);

        //devolvemos un objeto AuthReponse con el patrón de diseño Builder, junto a un token que hay que generar
        return AuthReponse.builder()
                .token(jwtService. getToken(user)) //servicio para generar el token con los datos del usuario
                .build();

    }
}
