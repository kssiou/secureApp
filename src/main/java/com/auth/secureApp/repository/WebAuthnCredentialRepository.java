package com.auth.secureApp.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.auth.secureApp.entity.User;
import com.auth.secureApp.entity.WebAuthnCredential;

import java.util.List;

/**
 * Repository for storing and retrieving WebAuthn credentials.
 */
@Repository
public interface WebAuthnCredentialRepository extends JpaRepository<WebAuthnCredential, Long> {

    /**
     * Find a credential by its ID.
     *
     * @param credentialId The credential ID as a byte array
     * @return The matching credential or null if not found
     */
    WebAuthnCredential findByCredentialId(byte[] credentialId);

    /**
     * Find all credentials belonging to a specific user.
     *
     * @param user The user
     * @return List of credentials for the user
     */
    List<WebAuthnCredential> findByUser(User user);

    /**
     * Delete a credential by its ID.
     *
     * @param credentialId The credential ID as a byte array
     */
    void deleteByCredentialId(byte[] credentialId);

    /**
     * Count how many credentials a user has.
     *
     * @param user The user
     * @return Count of credentials
     */
    long countByUser(User user);
}