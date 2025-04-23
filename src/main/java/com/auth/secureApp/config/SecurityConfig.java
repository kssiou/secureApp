package com.auth.secureApp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.auth.secureApp.entity.RelyingParty;
import com.webauthn4j.WebAuthnManager;

import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors().and()  // Enable CORS
            .csrf().disable()  // Disable CSRF for API endpoints
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/", "/home", "/register", "/webauthn/**").permitAll()  // Add webauthn endpoints
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/dashboard")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutSuccessUrl("/")
                .permitAll()
            )
            .exceptionHandling(exception -> exception
                .accessDeniedPage("/access-denied")
            );
        
        return http.build();
    }
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Collections.singletonList("*"));  // Allow all origins
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));  // Allow all methods
        configuration.setAllowedHeaders(Collections.singletonList("*"));  // Allow all headers
        configuration.setExposedHeaders(Arrays.asList("Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"));
        configuration.setAllowCredentials(false);  // Important: must be false when using "*" for origins
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
    
    @Bean
    public WebAuthnManager webAuthnManager() {
        return WebAuthnManager.createNonStrictWebAuthnManager();
    }
    
    @Bean
    public RelyingParty relyingParty() {
        return new RelyingParty(
            "localhost", // Just use localhost as the RP ID
            "Passkey Auth Demo", 
            "http://localhost:4200" // Your frontend URL
        );
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}