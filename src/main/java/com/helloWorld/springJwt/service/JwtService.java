package com.helloWorld.springJwt.service;

import com.helloWorld.springJwt.model.User;
import com.helloWorld.springJwt.repository.TokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {

    private final String SECRET_KEY = "946a2647c6260b5ebc0f864fdff5198e5ebc4e0b4f3ab495079330b30f5f00bc";
    private final Integer EXPIRATION_DURATION_MILLI = 86_400_000; // Milli sec in a day
    private final TokenRepository tokenRepository;

    public JwtService(TokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    public String extractUsername(String token){
        return extractClaim(token,Claims::getSubject);
    }

    public boolean isValid(String token, User user){
       String username = extractUsername(token);

       boolean isValidToken = tokenRepository.findByToken(token)
               .map(t->!t.isLoggedOut()).orElse(false);

       return username.equals(user.getName()) && !isTokenExpired(token) && isValidToken;
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
    private Date extractExpiration(String token){
        return extractClaim(token,Claims::getExpiration);
    }


    public <T> T extractClaim(String token, Function<Claims,T> resolver){
        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }

    private Claims extractAllClaims(String token){
        return Jwts
                .parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String generateToken(User user){
        return Jwts.builder()
                .subject(user.getName())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_DURATION_MILLI))
                .signWith(getSigningKey())
                .compact();
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64URL.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
