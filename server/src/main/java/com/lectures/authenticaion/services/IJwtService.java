package com.lectures.authenticaion.services;

public interface IJwtService {
    String generateToken(String username);
    String getUsername(String token);
}
