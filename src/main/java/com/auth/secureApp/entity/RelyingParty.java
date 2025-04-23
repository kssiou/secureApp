package com.auth.secureApp.entity;

/**
 * Represents the Relying Party in WebAuthn terminology (the service using WebAuthn).
 */
public class RelyingParty {

    private final String id;
    private final String name;
    private final String origin;

    /**
     * Creates a new RelyingParty instance.
     *
     * @param id     The RP ID (typically the domain name without protocol or port)
     * @param name   The human-readable name of the service
     * @param origin The full origin (https://example.com)
     */
    public RelyingParty(String id, String name, String origin) {
        this.id = id;
        this.name = name;
        this.origin = origin;
    }

    /**
     * @return The RP ID (domain name)
     */
    public String getId() {
        return id;
    }

    /**
     * @return The human-readable name of the service
     */
    public String getName() {
        return name;
    }

    /**
     * @return The full origin (https://example.com)
     */
    public String getOrigin() {
        return origin;
    }
}