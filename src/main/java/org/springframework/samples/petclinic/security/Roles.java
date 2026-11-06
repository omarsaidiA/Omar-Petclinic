package org.springframework.samples.petclinic.security;

import org.springframework.stereotype.Component;

/**
 * Spring authorities derived from the Keycloak realm roles ADMIN, VET and OWNER.
 * Exposed as a bean so {@code @PreAuthorize} expressions can reference them as {@code @roles.ADMIN}.
 */
@Component
public class Roles {

    public final String ADMIN = "ROLE_ADMIN";
    public final String VET = "ROLE_VET";
    public final String OWNER = "ROLE_OWNER";
}
