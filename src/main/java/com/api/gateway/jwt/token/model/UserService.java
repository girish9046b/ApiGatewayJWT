package com.api.gateway.jwt.token.model;

import org.springframework.stereotype.Service;

import com.api.gateway.jwt.token.error.UserNotFoundException;
@Service
public interface UserService {
    public void saveUser(User user);
    public User getUserByNameAndPassword(String name, String password) throws UserNotFoundException;
    public User getUserByName(String name) throws UserNotFoundException;
}
