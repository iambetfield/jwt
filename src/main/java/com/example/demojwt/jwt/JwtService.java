package com.example.demojwt.jwt;

import com.example.demojwt.entities.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY= "83393339339393939393aasadsdawaweaweaweawea4sfsdfs43434r34sefs9";

    //pasamos por parámetros un UserDetails

    public String getToken(UserDetails user) {
                //llamamos a otro metodo que nos trae un map con pares Key/Value, y un usuario
        return getToken(new HashMap<>(), user);
    }

    private String getToken(Map<String,Object> extraClaims, UserDetails user) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(user.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
                //usamos un método getKey y un método de encriptación
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact(); //crea el objeto y lo serializa

    }

    private Key getKey() {
        byte[] KeyBytes = Decoders.BASE64.decode(SECRET_KEY); //llevamos la key a BASE64 para mandarla como Key ala firma del token
        return Keys.hmacShaKeyFor(KeyBytes); //crea una instancia de la key
    }

    public String getUsernameFromToken(String token) {
        return getClaim(token, Claims::getSubject); //le pasamos eltoken y el claim en particular, donde tenemos el username
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        //tenemos que tener en cuenta la fecha de expiracion
        //1 verificamos que el username del token corresponde con el de userDetails
        final String username = getUsernameFromToken(token);
        //si ese username es igual al UserDetails y además el token no ha expirado
        return (username.equals(userDetails.getUsername())&& !isTokenExpired(token));
    }

    //creamos un método privado que obtiene los claims del token

    private Claims getAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

    }

    public <T> T getClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = getAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Date getExpiration(String token){
        return getClaim(token, Claims::getExpiration); //devuelve la fecha de expiración
    }

    private boolean isTokenExpired(String token){
        return getExpiration(token).before(new Date()); //veo gracias almétodo before si ha expirado
    }
}
