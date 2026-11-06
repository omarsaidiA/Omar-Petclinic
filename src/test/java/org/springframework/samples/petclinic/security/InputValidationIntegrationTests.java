package org.springframework.samples.petclinic.security;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.JwtRequestPostProcessor;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

/**
 * Bean Validation on request bodies, path and query parameters: invalid input is rejected with 400
 * before it reaches the service layer.
 */
@SpringBootTest
@Transactional
class InputValidationIntegrationTests {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    private static JwtRequestPostProcessor admin() {
        return jwt()
            .jwt(builder -> builder.claim("realm_access", Map.of("roles", List.of("ADMIN"))))
            .authorities(new KeycloakRealmRoleConverter());
    }

    @Test
    void rejectsNegativePathId() throws Exception {
        mockMvc.perform(get("/api/owners/-1").with(admin())).andExpect(status().isBadRequest());
    }

    @Test
    void rejectsOversizedQueryParameter() throws Exception {
        mockMvc.perform(get("/api/owners").param("lastName", "x".repeat(31)).with(admin()))
            .andExpect(status().isBadRequest());
    }

    @Test
    void rejectsPageSizeAboveMaximum() throws Exception {
        mockMvc.perform(get("/api/v2/owners").param("size", "100000").with(admin()))
            .andExpect(status().isBadRequest());
    }

    @Test
    void rejectsOwnerWithInjectedCharacters() throws Exception {
        String owner = "{\"firstName\":\"<script>alert(1)</script>\",\"lastName\":\"Doe\",\"address\":\"1 Main St\","
            + "\"city\":\"Paris\",\"telephone\":\"0612345678\"}";
        mockMvc.perform(post("/api/owners").with(admin()).contentType(MediaType.APPLICATION_JSON).content(owner))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.title").value("Bad Request"));
    }

    @Test
    void rejectsShortUserPassword() throws Exception {
        String user = "{\"username\":\"newuser\",\"password\":\"short\",\"enabled\":true,\"roles\":[{\"name\":\"VET\"}]}";
        mockMvc.perform(post("/api/users").with(admin()).contentType(MediaType.APPLICATION_JSON).content(user))
            .andExpect(status().isBadRequest());
    }

    @Test
    void rejectsTooManyRoles() throws Exception {
        String user = "{\"username\":\"newuser\",\"password\":\"Str0ng-Passw0rd!\",\"enabled\":true,"
            + "\"roles\":[{\"name\":\"A\"},{\"name\":\"B\"},{\"name\":\"C\"},{\"name\":\"D\"}]}";
        mockMvc.perform(post("/api/users").with(admin()).contentType(MediaType.APPLICATION_JSON).content(user))
            .andExpect(status().isBadRequest());
    }
}
