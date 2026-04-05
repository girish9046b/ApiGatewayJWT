package com.api.gateway.jwt.token.jwt;

import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.WebFilter;



@Configuration
@EnableWebFluxSecurity
//@EnableWebSecurity
public class SecurityConfigJWT {

	private static final Logger logger = LoggerFactory.getLogger(SecurityConfigJWT.class);

//	private JwtFilter jwtFilter;
//	// private CustomUserDetailsService userDetailsService;
//
//	// Constructor for injection (Spring automatically injects SecurityConfigJWT
//	// here)
//	public SecurityConfigJWT(JwtFilter jwtFilter) {
//		this.jwtFilter = jwtFilter;
//		// this.userDetailsService = userDetailsService;
//	}

	
	  @Bean
	    public SecurityWebFilterChain springSecurityFilterChain(
	            ServerHttpSecurity http, WebFilter jwtFilter) {
		  logger.info("........SecurityWebFilterChainSecurityWebFilterChain.......");
	        return http
	            .csrf(ServerHttpSecurity.CsrfSpec::disable) // Disable CSRF for APIs
	            .authorizeExchange(exchanges -> exchanges
	                .pathMatchers("/api/student/token/**","/TOKENGENERATORAPI/**").permitAll()
	                .anyExchange().authenticated()
	            )
	            // Add custom filter before authentication in the chain
	            .addFilterAt(jwtFilter, SecurityWebFiltersOrder.AUTHENTICATION)
	            .build();
	    }
	
	
//	@Bean
//	public SecurityFilterChain securityFilterChain(HttpSecurity http) {
//		logger.info("........securityFilterChainsecurityFilterChain.......");
////	    	http
////            .csrf(AbstractHttpConfigurer::disable)
////            .authorizeHttpRequests(auth -> auth
////                .anyRequest().authenticated()
////            )
////            .httpBasic(Customizer.withDefaults());
//
//		http.csrf(csrf -> csrf.disable()) // Disable CSRF for stateless APIs
//				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Use
//				.authorizeHttpRequests(auth -> auth
//						.requestMatchers("/api/student/token/**", "/api/student/register/**", "/api/student/**")
//						.permitAll() // Allow
//						.requestMatchers("/api/student/**").permitAll()// to bypass jwtfilter and use the controller
//																		// validation
//						.anyRequest().authenticated() // Secure all other endpoints
//				);
//
//		// Add the custom JWT filter before the standard
//		// UsernamePasswordAuthenticationFilter
//		http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
//
//		return http.build();
//	}
	
//	
//	 @Bean
//	    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,
//	                                                     ReactiveAuthenticationManager authenticationManager,
//	                                                     ServerAuthenticationConverter authenticationConverter) {
//	        AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(authenticationManager);
//	        authenticationWebFilter.setServerAuthenticationConverter(authenticationConverter);
//
//	        return http
//	                .authorizeExchange(exchanges -> exchanges
//	                        .pathMatchers("/api/student/token/**").permitAll()
//	                        .anyExchange().authenticated()
//	                )
//	                .addFilterAt(authenticationWebFilter, SecurityWebFiltersOrder.AUTHENTICATION)
//	                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
//	                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
//	                .csrf(ServerHttpSecurity.CsrfSpec::disable)
//	                .cors(ServerHttpSecurity.CorsSpec::disable)
//	                .build();
//	    }
	

//    @Bean
//    public SecurityFilterChain  securityFilterChain(HttpSecurity http) throws Exception {
//    	http.csrf(csrf -> csrf.disable())
//    	.authorizeHttpRequests(auth -> auth
//                .requestMatchers("/public/**").permitAll() // Use requestMatchers
//                .anyRequest().authenticated()
//        .requestMatchers("/api/student/login/*")
//       //antMatchers("/api/student/authenticate")//for angular
//        .permitAll()
//        .anyRequest()
//        .authenticated()
//        //.and()
//        //.sessionManagement()
//        //.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//        );
//http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
//return http.build();
//
//    }

	// Configure the AuthenticationProvider to use the custom UserDetailsService and
	// passwordEncoder
//	    @Bean
//	    public AuthenticationProvider authenticationProvider() {
//	        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
//	        provider.setPasswordEncoder(passwordEncoder());
//	        return provider;
//	    }

	// You can also define other beans, like a PasswordEncoder
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	// To expose the AuthenticationManager as a bean, you can create a bean of type
	// AuthenticationManager
//	@Bean
//	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) {
//		return authenticationConfiguration.getAuthenticationManager();
//	}

	// To allow cross origin request access
	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList("*"));
		configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "OPTIONS", "PATCH", "DELETE"));
		configuration.setAllowCredentials(true);
		configuration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));
		configuration.setMaxAge((long) 10);
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}
}