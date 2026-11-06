package org.springframework.samples.petclinic.security;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.JwtRequestPostProcessor;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

/**
 * End-to-end authorization tests through the real security filter chain.
 * <p>
 * Tokens are built from Keycloak-shaped claims ({@code realm_access.roles}, {@code owner_id}) and go through
 * {@link KeycloakRealmRoleConverter}, so these tests also cover the role mapping. Each role is tested for
 * both allowed and denied access. Write tests run in a rolled-back transaction.
 */
@SpringBootTest
@Transactional
class SecurityIntegrationTests {

    private static final String VISIT_JSON = "{\"date\":\"2013-01-01\",\"description\":\"checkup\"}";
    private static final String PET_TYPE_JSON = "{\"name\":\"hamster\"}";
    private static final String OWNER_JSON = "{\"firstName\":\"Eve\",\"lastName\":\"Attacker\",\"address\":\"1 Main St\","
        + "\"city\":\"Paris\",\"telephone\":\"0612345678\"}";

    @Autowired
    private WebApplicationContext context;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    private static JwtRequestPostProcessor token(String role, Map<String, Object> extraClaims) {
        return jwt()
            .jwt(builder -> {
                builder.claim("realm_access", Map.of("roles", List.of(role)))
                    .claim("preferred_username", role.toLowerCase());
                extraClaims.forEach(builder::claim);
            })
            .authorities(new KeycloakRealmRoleConverter());
    }

    private static JwtRequestPostProcessor admin() {
        return token("ADMIN", Map.of());
    }

    private static JwtRequestPostProcessor vet() {
        return token("VET", Map.of());
    }

    private static JwtRequestPostProcessor owner(long ownerId) {
        return token("OWNER", Map.of("owner_id", ownerId));
    }

    @Nested
    class Anonymous {

        @Test
        void apiRequiresAToken() throws Exception {
            mockMvc.perform(get("/api/owners"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));
        }

        @Test
        void swaggerUiIsServedWithItsOwnCsp() throws Exception {
            // Guards the Swagger UI webjar override: a version mismatch with springdoc silently returns 404
            mockMvc.perform(get("/swagger-ui/index.html"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Security-Policy", containsString("default-src 'self'")));
        }

        @Test
        void healthIsPublic() throws Exception {
            mockMvc.perform(get("/actuator/health")).andExpect(status().isOk());
        }

        @Test
        void otherActuatorEndpointsAreNotPublic() throws Exception {
            mockMvc.perform(get("/actuator/env")).andExpect(status().isUnauthorized());
            mockMvc.perform(get("/actuator/beans")).andExpect(status().isUnauthorized());
        }

        @Test
        void tokenWithUnknownRoleGetsNoAccess() throws Exception {
            mockMvc.perform(get("/api/pettypes").with(token("SUPERUSER", Map.of())))
                .andExpect(status().isForbidden());
        }
    }

    @Nested
    class Admin {

        @Test
        void canReadEverything() throws Exception {
            mockMvc.perform(get("/api/owners").with(admin())).andExpect(status().isOk());
            mockMvc.perform(get("/api/vets").with(admin())).andExpect(status().isOk());
            mockMvc.perform(get("/api/specialties").with(admin())).andExpect(status().isOk());
        }

        @Test
        void canManageReferenceData() throws Exception {
            mockMvc.perform(post("/api/pettypes").with(admin())
                    .contentType(MediaType.APPLICATION_JSON).content(PET_TYPE_JSON))
                .andExpect(status().isCreated());
        }

        @Test
        void canManageOwners() throws Exception {
            mockMvc.perform(post("/api/owners").with(admin())
                    .contentType(MediaType.APPLICATION_JSON).content(OWNER_JSON))
                .andExpect(status().isCreated());
        }

        @Test
        void cannotUpdateAPetThroughAnotherOwnersUrl() throws Exception {
            // BOLA regression: pet 7 belongs to owner 6, not owner 1
            String pet = "{\"name\":\"Hijacked\",\"birthDate\":\"2012-09-04\",\"type\":{\"id\":1,\"name\":\"cat\"}}";
            mockMvc.perform(put("/api/owners/1/pets/7").with(admin())
                    .contentType(MediaType.APPLICATION_JSON).content(pet))
                .andExpect(status().isNotFound());
        }

        @Test
        void createdUserPasswordIsNeverReturned() throws Exception {
            String user = "{\"username\":\"newvet\",\"password\":\"Str0ng-Passw0rd!\",\"enabled\":true,\"roles\":[{\"name\":\"VET\"}]}";
            mockMvc.perform(post("/api/users").with(admin()).contentType(MediaType.APPLICATION_JSON).content(user))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(content().string(not(containsString("Str0ng-Passw0rd!"))));
        }
    }

    @Nested
    class Vet {

        @Test
        void canReadOwnersAndPets() throws Exception {
            mockMvc.perform(get("/api/owners").with(vet())).andExpect(status().isOk());
            mockMvc.perform(get("/api/owners/1").with(vet())).andExpect(status().isOk());
            mockMvc.perform(get("/api/pets").with(vet())).andExpect(status().isOk());
            mockMvc.perform(get("/api/pets/1").with(vet())).andExpect(status().isOk());
        }

        @Test
        void canManageVisits() throws Exception {
            mockMvc.perform(get("/api/visits").with(vet())).andExpect(status().isOk());
            mockMvc.perform(put("/api/visits/1").with(vet())
                    .contentType(MediaType.APPLICATION_JSON).content(VISIT_JSON))
                .andExpect(status().isNoContent());
        }

        @Test
        void cannotAddAVisitToAPetThroughAnotherOwnersUrl() throws Exception {
            // BOLA regression: pet 7 belongs to owner 6, not owner 1
            mockMvc.perform(post("/api/owners/1/pets/7/visits").with(vet())
                    .contentType(MediaType.APPLICATION_JSON).content(VISIT_JSON))
                .andExpect(status().isNotFound());
            mockMvc.perform(post("/api/owners/6/pets/7/visits").with(vet())
                    .contentType(MediaType.APPLICATION_JSON).content(VISIT_JSON))
                .andExpect(status().isCreated());
        }

        @Test
        void cannotModifyOwnersOrPets() throws Exception {
            mockMvc.perform(post("/api/owners").with(vet())
                    .contentType(MediaType.APPLICATION_JSON).content(OWNER_JSON))
                .andExpect(status().isForbidden());
            mockMvc.perform(delete("/api/pets/1").with(vet())).andExpect(status().isForbidden());
        }

        @Test
        void cannotManageReferenceDataOrUsers() throws Exception {
            mockMvc.perform(post("/api/pettypes").with(vet())
                    .contentType(MediaType.APPLICATION_JSON).content(PET_TYPE_JSON))
                .andExpect(status().isForbidden());
            mockMvc.perform(delete("/api/vets/1").with(vet())).andExpect(status().isForbidden());
            mockMvc.perform(post("/api/users").with(vet())
                    .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isForbidden());
        }
    }

    @Nested
    class Owner {

        @Test
        void canReadOwnProfileAndPets() throws Exception {
            mockMvc.perform(get("/api/owners/1").with(owner(1)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1));
            mockMvc.perform(get("/api/owners/1/pets/1").with(owner(1))).andExpect(status().isOk());
            mockMvc.perform(get("/api/pets/1").with(owner(1))).andExpect(status().isOk());
        }

        @Test
        void canReadOwnVisits() throws Exception {
            // Visit 1 belongs to pet 7, owned by owner 6
            mockMvc.perform(get("/api/visits/1").with(owner(6))).andExpect(status().isOk());
        }

        @Test
        void cannotReadAnotherOwnersData() throws Exception {
            mockMvc.perform(get("/api/owners/2").with(owner(1))).andExpect(status().isForbidden());
            mockMvc.perform(get("/api/pets/2").with(owner(1))).andExpect(status().isForbidden());
            mockMvc.perform(get("/api/visits/1").with(owner(1))).andExpect(status().isForbidden());
            // Pet 7 exists but belongs to owner 6
            mockMvc.perform(get("/api/owners/1/pets/7").with(owner(1))).andExpect(status().isNotFound());
        }

        @Test
        void cannotListEveryone() throws Exception {
            mockMvc.perform(get("/api/owners").with(owner(1))).andExpect(status().isForbidden());
            mockMvc.perform(get("/api/pets").with(owner(1))).andExpect(status().isForbidden());
            mockMvc.perform(get("/api/visits").with(owner(1))).andExpect(status().isForbidden());
            mockMvc.perform(get("/api/vets").with(owner(1))).andExpect(status().isForbidden());
        }

        @Test
        void isReadOnlyEvenOnOwnData() throws Exception {
            mockMvc.perform(put("/api/owners/1").with(owner(1))
                    .contentType(MediaType.APPLICATION_JSON).content(OWNER_JSON))
                .andExpect(status().isForbidden());
            mockMvc.perform(delete("/api/pets/1").with(owner(1))).andExpect(status().isForbidden());
            mockMvc.perform(post("/api/owners/1/pets/1/visits").with(owner(1))
                    .contentType(MediaType.APPLICATION_JSON).content(VISIT_JSON))
                .andExpect(status().isForbidden());
        }

        @Test
        void missingOwnerIdClaimGrantsNothing() throws Exception {
            mockMvc.perform(get("/api/owners/1").with(token("OWNER", Map.of())))
                .andExpect(status().isForbidden());
        }

        @Test
        void canReadReferenceData() throws Exception {
            mockMvc.perform(get("/api/pettypes").with(owner(1))).andExpect(status().isOk());
        }
    }

    @Nested
    class HardeningHeadersCorsAndErrors {

        @Test
        void apiResponsesCarrySecurityHeaders() throws Exception {
            mockMvc.perform(get("/api/vets").with(admin()).secure(true))
                .andExpect(header().string("Content-Security-Policy", containsString("default-src 'none'")))
                .andExpect(header().string("Content-Security-Policy", containsString("frame-ancestors 'none'")))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Strict-Transport-Security", containsString("max-age=31536000")));
        }

        @Test
        void corsAllowsOnlyConfiguredOrigins() throws Exception {
            mockMvc.perform(options("/api/vets")
                    .header(HttpHeaders.ORIGIN, "https://frontend.example.com")
                    .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET"))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "https://frontend.example.com"));

            mockMvc.perform(options("/api/vets")
                    .header(HttpHeaders.ORIGIN, "https://evil.example.com")
                    .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET"))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
        }

        @Test
        void errorsDoNotLeakInternals() throws Exception {
            mockMvc.perform(get("/api/owners/not-a-number").with(admin()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.title").value("Bad Request"))
                .andExpect(content().string(not(containsString("Exception"))))
                .andExpect(content().string(not(containsString("at org."))));

            mockMvc.perform(post("/api/owners").with(admin())
                    .contentType(MediaType.APPLICATION_JSON).content("{not json"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(not(containsString("Exception"))));
        }
    }
}
