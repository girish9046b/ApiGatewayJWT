package com.api.gateway.jwt.token.error;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

// Option 1: Use @ResponseStatus for simple cases

@ResponseStatus(value = HttpStatus.NOT_FOUND, reason = "User not found")
public class UserNotFoundException extends RuntimeException  {
	
	private static final Logger logger = LoggerFactory.getLogger(UserNotFoundException.class);
	
    public UserNotFoundException(String message) {
    	logger.info("..................UserNotFoundException.......");
        super(message);
    }
}
