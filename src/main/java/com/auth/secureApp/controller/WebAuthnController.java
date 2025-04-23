package com.auth.secureApp.controller;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpSession;




import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.auth.secureApp.entity.RelyingParty;
import com.auth.secureApp.entity.User;
import com.auth.secureApp.entity.WebAuthnCredential;
import com.auth.secureApp.repository.UserRepository;
import com.auth.secureApp.repository.WebAuthnCredentialRepository;
import com.webauthn4j.WebAuthnManager;

import javax.servlet.http.HttpServletRequest;

import java.util.Optional;

@RestController
@RequestMapping("/webauthn")
public class WebAuthnController {

    @Autowired
    private WebAuthnManager webAuthnManager;
    
    @Autowired
    private RelyingParty relyingParty;
    
    @Autowired
    private UserRepository userRepository; // Existing user repository
    
    @Autowired
    private WebAuthnCredentialRepository credentialRepository; // New repository

    // Store challenges in session to keep it simple
    @PostMapping("/register/start")
    public Map<String, Object> startRegistration(
            @RequestBody Map<String, String> request, 
            HttpSession session) {
        
        String username = request.get("username");
        
        // Find existing user (they should be already registered with username/password)
        Optional<User>  user = userRepository.findByUsername(username);
        
        if (user == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User not found");
        }
        
        // Generate random challenge
        byte[] challenge = new byte[32];
        new SecureRandom().nextBytes(challenge);
        session.setAttribute("challenge", challenge);
        
        // Create registration options
        Map<String, Object> options = new HashMap<>();
        options.put("challenge", Base64.getEncoder().encodeToString(challenge));
        options.put("rp", Map.of(
            "name", relyingParty.getName(),
            "id", relyingParty.getId()
        ));
        options.put("user", Map.of(
            "id", Base64.getEncoder().encodeToString(user.get().getId().toString().getBytes()),

            "name", username,
            "displayName", username
        ));
        options.put("pubKeyCredParams", List.of(
            Map.of("type", "public-key", "alg", -7), // ES256
            Map.of("type", "public-key", "alg", -257) // RS256
        ));
        options.put("timeout", 60000);
        options.put("attestation", "none");
        options.put("authenticatorSelection", Map.of(
            "authenticatorAttachment", "platform", // For passkeys
            "requireResidentKey", true, // For passkeys
            "userVerification", "required"
        ));
        
        return options;
    }
    
    @PostMapping("/register/finish")
    public Map<String, Object> finishRegistration(
            @RequestBody Map<String, Object> request,
            HttpSession session) {
        
        // Get saved challenge
        byte[] challenge = (byte[]) session.getAttribute("challenge");
        session.removeAttribute("challenge");
        
        if (challenge == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "No challenge found");
        }
        
        try {
            // Extract credential data from request
            Map<String, Object> credential = (Map<String, Object>) request.get("credential");
            String credentialId = (String) credential.get("id");
            String rawId = (String) credential.get("rawId");
            String clientDataJSON = (String) credential.get("clientDataJSON");
            String attestationObject = (String) credential.get("attestationObject");
            
            // Validate credential (simplified)
            // In a real implementation, use webAuthnManager for proper validation
            byte[] rawIdBytes = Base64.getDecoder().decode(rawId);
            byte[] clientDataJSONBytes = Base64.getDecoder().decode(clientDataJSON);
            byte[] attestationObjectBytes = Base64.getDecoder().decode(attestationObject);
            
            // Extract username from the request
            String username = (String) request.get("username");
            Optional<User>  user = userRepository.findByUsername(username);
            
            // Create and save credential
            WebAuthnCredential webAuthnCredential = new WebAuthnCredential();
            webAuthnCredential.setUser(user.get()); 
            webAuthnCredential.setCredentialId(rawIdBytes);
            // In real implementation, extract public key from attestation
            webAuthnCredential.setPublicKey(new byte[]{0}); // Placeholder
            webAuthnCredential.setSignatureCount(0);
            credentialRepository.save(webAuthnCredential);
            
            return Map.of("success", true);
        } catch (Exception e) {
            return Map.of("success", false, "error", e.getMessage());
        }
    }
    
    @PostMapping("/authenticate/start")
    public Map<String, Object> startAuthentication(
            @RequestBody Map<String, String> request,
            HttpSession session) {
        
        // Generate random challenge
        byte[] challenge = new byte[32];
        new SecureRandom().nextBytes(challenge);
        session.setAttribute("challenge", challenge);
        
        // Create authentication options
        Map<String, Object> options = new HashMap<>();
        options.put("challenge", Base64.getEncoder().encodeToString(challenge));
        options.put("rpId", relyingParty.getId());
        options.put("timeout", 60000);
        options.put("userVerification", "required");
        
        // If username provided, include allowCredentials
        String username = request.get("username");
        if (username != null && !username.isEmpty()) {
            // Using Optional properly - check if user exists first
            Optional<User> userOptional = userRepository.findByUsername(username);
            
            if (userOptional.isPresent()) {
                User user = userOptional.get();
                // Get credentials from user
                List<WebAuthnCredential> credentials = credentialRepository.findByUser(user);
                
                if (credentials != null && !credentials.isEmpty()) {
                    List<Map<String, Object>> allowCredentials = credentials.stream()
                        .map(cred -> {
                            Map<String, Object> credMap = new HashMap<>();
                            credMap.put("id", Base64.getEncoder().encodeToString(cred.getCredentialId()));
                            credMap.put("type", "public-key");
                            return credMap;
                        })
                        .collect(Collectors.toList());
                    
                    options.put("allowCredentials", allowCredentials);
                }
            }
            // No need to throw an exception if user not found during authentication
            // Just proceed without allowCredentials
        }
        
        return options;
    }   
    @PostMapping("/authenticate/finish")
    public Map<String, Object> finishAuthentication(
            @RequestBody Map<String, Object> request,
            HttpSession session,
            HttpServletRequest httpRequest) {
        
        // Get saved challenge
        byte[] challenge = (byte[]) session.getAttribute("challenge");
        session.removeAttribute("challenge");
        
        if (challenge == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "No challenge found");
        }
        
        try {
            // Extract credential data
            Map<String, Object> credential = (Map<String, Object>) request.get("credential");
            String credentialId = (String) credential.get("id");
            String clientDataJSON = (String) credential.get("clientDataJSON");
            String authenticatorData = (String) credential.get("authenticatorData");
            String signature = (String) credential.get("signature");
            String userHandle = (String) credential.get("userHandle");
            
            // Decode credential ID
            byte[] credentialIdBytes = Base64.getDecoder().decode(
                (String) credential.get("rawId"));
            
            // Find credential in database
            WebAuthnCredential storedCredential = credentialRepository.findByCredentialId(credentialIdBytes);
            
            if (storedCredential == null) {
                return Map.of("success", false, "message", "Credential not found");
            }
            
            // In a real implementation, validate the assertion with webAuthnManager
            
            // Get user from credential
            User user = storedCredential.getUser();
            
            // Create authentication token for Spring Security
            UsernamePasswordAuthenticationToken authToken = 
                new UsernamePasswordAuthenticationToken(
                    user.getUsername(), 
                    null, 
                    List.of(new SimpleGrantedAuthority("ROLE_USER"))
                );
            
            // Set authentication in context
            SecurityContextHolder.getContext().setAuthentication(authToken);
            
            // For session-based auth, create session
            HttpSession newSession = httpRequest.getSession(true);
            newSession.setAttribute(
                "SPRING_SECURITY_CONTEXT", 
                SecurityContextHolder.getContext()
            );
            
            return Map.of(
                "success", true, 
                "redirectUrl", "/dashboard"
            );
        } catch (Exception e) {
            return Map.of("success", false, "error", e.getMessage());
        }
    }
}