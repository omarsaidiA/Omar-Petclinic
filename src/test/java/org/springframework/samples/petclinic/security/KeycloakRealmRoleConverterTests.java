package org.springframework.samples.petclinic.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

class KeycloakRealmRoleConverterTests {

    private final KeycloakRealmRoleConverter converter = new KeycloakRealmRoleConverter();

    private static Jwt jwtWithClaims(Map<String, Object> claims) {
        Jwt.Builder builder = Jwt.withTokenValue("token")
            .header("alg", "RS256")
            .subject("user")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(300));
        claims.forEach(builder::claim);
        return builder.build();
    }

    private List<String> authorities(Jwt jwt) {
        return converter.convert(jwt).stream().map(GrantedAuthority::getAuthority).toList();
    }

    @Test
    void mapsRealmRolesToSpringAuthorities() {
        Jwt jwt = jwtWithClaims(Map.of("realm_access", Map.of("roles", List.of("ADMIN", "VET"))));
        assertThat(authorities(jwt)).containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_VET");
    }

    @Test
    void ignoresRolesUnknownToTheApplication() {
        Jwt jwt = jwtWithClaims(Map.of("realm_access",
            Map.of("roles", List.of("OWNER", "offline_access", "default-roles-omar-petclinic", "SUPERUSER"))));
        assertThat(authorities(jwt)).containsExactly("ROLE_OWNER");
    }

    @Test
    void returnsNoAuthorityWhenRealmAccessIsMissing() {
        Jwt jwt = jwtWithClaims(Map.of("scope", "openid"));
        assertThat(authorities(jwt)).isEmpty();
    }

    @Test
    void returnsNoAuthorityWhenRolesClaimHasAnUnexpectedShape() {
        Jwt jwt = jwtWithClaims(Map.of("realm_access", Map.of("roles", "ADMIN")));
        assertThat(authorities(jwt)).isEmpty();
    }
}
