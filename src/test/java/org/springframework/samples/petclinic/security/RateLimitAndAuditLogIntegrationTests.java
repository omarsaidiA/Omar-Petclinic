package org.springframework.samples.petclinic.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.JwtRequestPostProcessor;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Rate limiting and security audit logs, with low limits so they are reached quickly.
 * A dedicated context keeps these buckets away from the other test classes.
 */
@SpringBootTest(properties = {
    "petclinic.rate-limit.authenticated-per-minute=3",
    "petclinic.rate-limit.anonymous-per-minute=2"
})
@DirtiesContext
@ExtendWith(OutputCaptureExtension.class)
class RateLimitAndAuditLogIntegrationTests {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    private static JwtRequestPostProcessor user(String name, String role) {
        return jwt()
            .jwt(builder -> builder.subject(name).claim("preferred_username", name)
                .claim("realm_access", Map.of("roles", List.of(role))))
            .authorities(new KeycloakRealmRoleConverter());
    }

    @Test
    void authenticatedUserIsLimitedPerUser() throws Exception {
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(get("/api/pettypes").with(user("alice", "VET"))).andExpect(status().isOk());
        }
        mockMvc.perform(get("/api/pettypes").with(user("alice", "VET")))
            .andExpect(status().isTooManyRequests())
            .andExpect(header().exists(HttpHeaders.RETRY_AFTER));
        // Another user has an independent bucket
        mockMvc.perform(get("/api/pettypes").with(user("bob", "VET"))).andExpect(status().isOk());
    }

    @Test
    void anonymousCallersAreLimitedPerIp() throws Exception {
        mockMvc.perform(get("/api/pettypes").with(r -> { r.setRemoteAddr("203.0.113.7"); return r; }))
            .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/pettypes").with(r -> { r.setRemoteAddr("203.0.113.7"); return r; }))
            .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/pettypes").with(r -> { r.setRemoteAddr("203.0.113.7"); return r; }))
            .andExpect(status().isTooManyRequests());
    }

    @Test
    void healthChecksAreNeverLimited() throws Exception {
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(get("/actuator/health")).andExpect(status().isOk());
        }
    }

    @Test
    void accessDeniedIsAuditedWithoutSensitiveData(CapturedOutput output) throws Exception {
        JwtRequestPostProcessor mallory = jwt()
            .jwt(builder -> builder.tokenValue("secret-token-value").subject("mallory")
                .claim("realm_access", Map.of("roles", List.of("OWNER"))))
            .authorities(new KeycloakRealmRoleConverter());
        mockMvc.perform(get("/api/vets").with(mallory)).andExpect(status().isForbidden());

        assertThat(output.getOut())
            .contains("event=access_denied")
            .contains("path=/api/vets")
            .contains("user=mallory")
            .doesNotContain("secret-token-value");
    }

    @Test
    void authenticationFailureIsAudited(CapturedOutput output) throws Exception {
        mockMvc.perform(get("/api/owners").with(r -> { r.setRemoteAddr("198.51.100.9"); return r; }))
            .andExpect(status().isUnauthorized());

        assertThat(output.getOut()).contains("event=authentication_failure").contains("ip=198.51.100.9");
    }

    @Test
    void logInjectionIsNeutralized() {
        assertThat(SecurityEventLogger.sanitize("/api/x\r\nevent=fake_success")).doesNotContain("\n").doesNotContain("\r");
    }
}
