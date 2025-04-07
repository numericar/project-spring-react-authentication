package com.lectures.authenticaion.services;

import java.time.Instant;
import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtServiceImpl implements IJwtService {

    @Value("jwt.private-key")
    private String PRIVATE_KEY;

    @Value("jwt.issuer")
    private String ISSUER;

    @Value("jwt.expire-in")
    private long EXPIRE_IN;

    @Override
    public String generateToken(String username) {
        Instant currentInstant = Instant.now();
        Instant expireInstant = currentInstant.plusMillis(this.EXPIRE_IN);

        return Jwts
                .builder()
                .issuer(this.ISSUER)
                .issuedAt(Date.from(currentInstant))
                .expiration(Date.from(expireInstant))
                .subject(username)
                .compact();
    }

    @Override
    public String getUsername(String token) {
        Jws<Claims> claims = this.getClaims(token);

        return claims.getPayload().getSubject();
    }

    private Jws<Claims> getClaims(String token) {
        try {
            SecretKey secretKey = Keys.hmacShaKeyFor(this.PRIVATE_KEY.getBytes());

            return Jwts
                    .parser()
                    .requireIssuer(this.ISSUER)
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token);
        } catch (ExpiredJwtException ex) {
            System.out.println("Token is expired");
            throw ex;
        } catch (JwtException ex) {
            System.out.println("Token is invalid");
            throw ex;
        }
    }

}
