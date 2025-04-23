package com.auth.secureApp.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "webauthn_credentials")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class WebAuthnCredential {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Lob
    @Column(length = 1024)
    private byte[] credentialId;
    
    @Lob
    @Column(length = 2048)
    private byte[] publicKey;
    
    @Column
    private long signatureCount;
    
    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;
}