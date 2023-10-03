package com.example.demojwt.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component                                //para crear filtros personalizados, y que se ejecute 1 sola vez x cada petición http
@RequiredArgsConstructor //requiere que se inicialicen todos los campos en el constructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    //agregamos los servicios
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;


    @Override   //realiza los filtros relacionados al token
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        //1. Hay que obtener el token del request, creamos un método a tal fin
        final String token = getTokenFromRequest(request);
        //2. también el username
        final String username;
        //si el token es nulo, devolvemos el control a la cadena de filtros
        if(token==null){
            filterChain.doFilter(request,response);
            return;
        }
        //si el token es distinto de nulo, tengo que acceder al username desde el token
        username = jwtService.getUsernameFromToken(token);

        //si el username es distinto de nulo y no lo encontramos en el SecurityContextHolder,lo buscamos en la DB
        if(username != null && SecurityContextHolder.getContext().getAuthentication()==null){
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            //si el token es valido.. -necesito tmb el userdetails-
            if(jwtService.isTokenValid(token, userDetails)){
                //actualizo el SecurityContextHolder, creando usernamePasswordAutToken
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                //por último seteamos el Details, pasando una instancia

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);

            }
        }
        filterChain.doFilter(request,response);

    }
    //va a devolver el token en un string, el parámestro es porque en el encabezado del request estaría el token
    private String getTokenFromRequest(HttpServletRequest request) {
                               //obtenemos la authenticacion en el encabezado
        final String authHeader=request.getHeader(HttpHeaders.AUTHORIZATION);

        //El encabezado va a comenzar con la palabra BEARER, y estamos trabajando con Token,
        //hay que extraer el token, para ello utilizamos la libreria StringUtils

        //si existe el texto en el encabeza y evaluar que el autheader comience con la palabra Bearer
        if(StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer")){ //si eso es correcto
            //extraigo a partir del caracter 7 hasta el final
            return authHeader.substring(7);
        } //caso contrario, null
        return null;
    }
}
