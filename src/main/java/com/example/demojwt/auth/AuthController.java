package com.example.demojwt.auth;

import com.example.demojwt.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping(value = "login")
    //representa toda la respuesta HTTP(header, payload, sign) y accedemos al cuerpo del msj donde obtenemos las credenciales, definidas en la clase LoginRequest
    public ResponseEntity<AuthReponse> login(@RequestBody LoginRequest request){
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping(value = "register")
    public ResponseEntity<AuthReponse> register(@RequestBody RegisterRequest request){
        return ResponseEntity.ok(authService.register(request));
    }


}
