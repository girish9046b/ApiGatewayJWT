package com.api.gateway.jwt.token.jwt;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.api.gateway.jwt.token.model.User;
import com.api.gateway.jwt.token.model.UserService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import reactor.core.publisher.Mono;

import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

@Component
public class JwtFilter implements  WebFilter  {

	private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);

	private JWTUtility jwtUtility;

	private UserService userService;

	public JwtFilter(JWTUtility jwtUtility, UserService userService) {
		super();
		this.jwtUtility = jwtUtility;
		this.userService = userService;
	}


	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		 // Logic before request goes to controller (similar to doFilterInternal)
//        String authorization = exchange.getRequest().getHeaders().getFirst("Authorization");
		String token = exchange.getRequest().getHeaders().getFirst("X-Custom-Token");
        logger.info(".......11...token userName......... {}--{}--{} ",exchange,exchange.getRequest(),exchange.getRequest().getHeaders());
        //String token = null;
		String userName = null;

//		if (null != authorization && authorization.startsWith("Bearer ")) {
//			token = authorization.substring(7);
		if(token !=null) {
			try {
			userName = jwtUtility.getUsernameFromToken(token);
			}
			catch(Exception e) {
				e.printStackTrace();
				throw new UsernameNotFoundException("Invalid token ,pls check");
			}
		}

		logger.info(".......22...token userName...ReactiveSecurityContextHolder...... {} ",ReactiveSecurityContextHolder.getContext().map(SecurityContext::getAuthentication));
		logger.info(".......22...token userName...userName..... {} ",userName);
		logger.info(".......22...token userName...token...... {} ",token);
		if (null != userName ) {
			User user = userService.getUserByName(userName);
			logger.info("......33....token userName......... {} , {} ", user.getUserName(), user.getPassword());

			if (jwtUtility.isValidateToken(token, user)) {
				logger.info(".....44....isValidateToken......... {} , {} ", user.getUserName(), user.getPassword());
				UsernamePasswordAuthenticationToken auth = 
	                    new UsernamePasswordAuthenticationToken(user, null, null);
				return chain.filter(exchange)
	                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
				

				//UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
				//		user, null,null);

				//usernamePasswordAuthenticationToken
				//		.setDetails(new WebAuthenticationDetailsSource().buildDetails((HttpServletRequest) exchange.getRequest()));

				//SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
			}

		}
        // Proceed with filter chain
//filterChain.doFilter((HttpServletRequest) exchange.getRequest(), (HttpServletRequest) exchange.getResponse());
        return chain.filter(exchange);
	}
	
	
//	 @Override
//	    public Mono<Void> filter1(ServerWebExchange exchange, WebFilterChain chain) {
//	        // Logic before request goes to controller (similar to doFilterInternal)
//	        String authorization = exchange.getRequest().getHeaders().getFirst("X-Custom-Token");
//	        String token = null;
//			String userName = null;
//
//			if (null != authorization && authorization.startsWith("Bearer ")) {
//				token = authorization.substring(7);
//				try {
//				userName = jwtUtility.getUsernameFromToken(token);
//				}
//				catch(Exception e) {
//					throw new UsernameNotFoundException("Invalid token ,pls check");
//				}
//			}
//			logger.info("..........token userName......... {}", userName);
//			if (null != userName && SecurityContextHolder.getContext().getAuthentication() == null) {
//				User user = userService.getUserByName(userName);
//				logger.info("..........token userName......... {} , {} ", user.getUserName(), user.getPassword());
//
//				if (jwtUtility.isValidateToken(token, user)) {
//					logger.info(".........isValidateToken......... {} , {} ", user.getUserName(), user.getPassword());
//					UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
//							user, null,null);
//
//					usernamePasswordAuthenticationToken
//							.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
//
//					SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
//				}
//
//			}
//	        // Proceed with filter chain
//	        return chain.filter(exchange);
//	    }
//	 
//	 
//	@Override
//	protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
//			FilterChain filterChain) throws ServletException, IOException {
//		String authorization = httpServletRequest.getHeader("X-Custom-Token");
//		String token = null;
//		String userName = null;
//
//		if (null != authorization && authorization.startsWith("Bearer ")) {
//			token = authorization.substring(7);
//			try {
//			userName = jwtUtility.getUsernameFromToken(token);
//			}
//			catch(Exception e) {
//				throw new UsernameNotFoundException("Invalid token ,pls check");
//			}
//		}
//		logger.info("..........token userName......... {}", userName);
//		if (null != userName && SecurityContextHolder.getContext().getAuthentication() == null) {
//			User user = userService.getUserByName(userName);
//			logger.info("..........token userName......... {} , {} ", user.getUserName(), user.getPassword());
//
//			if (jwtUtility.isValidateToken(token, user)) {
//				logger.info(".........isValidateToken......... {} , {} ", user.getUserName(), user.getPassword());
//				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
//						user, null,null);
//
//				usernamePasswordAuthenticationToken
//						.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
//
//				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
//			}
//
//		}
//		filterChain.doFilter(httpServletRequest, httpServletResponse);
//	}


}
