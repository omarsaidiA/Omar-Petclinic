package org.springframework.samples.petclinic.security;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Maps Keycloak realm roles ({@code realm_access.roles} claim) to Spring Security authorities.
 * <p>
 * Only the roles known to this application are kept (allow-list), so a role added in Keycloak
 * never grants access here by accident. {@code VET} becomes {@code ROLE_VET}, and so on.
 */
public class KeycloakRealmRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    static final String REALM_ACCESS_CLAIM = "realm_access";
    static final String ROLES_KEY = "roles";
    private static final Set<String> KNOWN_ROLES = Set.of("ADMIN", "VET", "OWNER");

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Map<String, Object> realmAccess = jwt.getClaimAsMap(REALM_ACCESS_CLAIM);
        if (realmAccess == null || !(realmAccess.get(ROLES_KEY) instanceof Collection<?> roles)) {
            return List.of();
        }
        return roles.stream()
            .filter(String.class::isInstance)
            .map(String.class::cast)
            .filter(KNOWN_ROLES::contains)
            .map(role -> (GrantedAuthority) new SimpleGrantedAuthority("ROLE_" + role))
            .toList();
    }
}
