package com.api.gateway.jwt.token.jwt;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import com.api.gateway.jwt.token.model.User;
import com.api.gateway.jwt.token.model.UserService;
import jakarta.servlet.http.HttpServletRequest;


@Component
public class HeaderTokenValidator {
	
	private static final Logger logger = LoggerFactory.getLogger(HeaderTokenValidator.class);

	private JWTUtility jwtUtility;

	private UserService userService;

	public HeaderTokenValidator(JWTUtility jwtUtility, UserService userService) {
		super();
		this.jwtUtility = jwtUtility;
		this.userService = userService;
	}
		
	public boolean doHeaderTokenValidator(Map<String, String> headers,HttpServletRequest httpServletRequest){
		String token = headers.get("X-Custom-Token");//httpServletRequest.getHeader("Authorization");
		String userName = null;
		logger.info("..........token token......... {}", token);
		if (null != token ) {
			try {
			userName = jwtUtility.getUsernameFromToken(token);
			}
			catch(Exception e) {
				throw new UsernameNotFoundException("Invalid token ,pls check");
			}
		}
		logger.info("..........token userName......... {}--{} ",SecurityContextHolder.getContext().getAuthentication(), userName);
		if (null != userName && SecurityContextHolder.getContext().getAuthentication() == null) {
			User user = userService.getUserByName(userName);
			logger.info("..........token userName......... {} , {} ", user.getUserName(), user.getPassword());

			if (jwtUtility.isValidateToken(token, user)) {
				logger.info(".........isValidateToken......... {} , {} ", user.getUserName(), user.getPassword());
				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
						user, null,null);
				usernamePasswordAuthenticationToken
						.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));

				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
				return true;
			}

		}
		return false;
	}

}
