package org.springframework.samples.petclinic.security;

import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Stateless OAuth2 resource server: every API call must carry a Keycloak-issued JWT.
 * <p>
 * Coarse rules live here (who may reach which path); fine-grained rules live on each controller
 * method with {@code @PreAuthorize} (enabled by {@link EnableMethodSecurity}).
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private static final long HSTS_MAX_AGE_SECONDS = 31_536_000L; // one year

    // A JSON API never renders HTML: nothing may be loaded, framed or submitted
    private static final String API_CSP =
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

    // Swagger UI needs its own scripts, styles and inline images
    private static final String DOCS_CSP =
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            + "object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

    private static final String[] DOCS_PATHS = {"/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs", "/v3/api-docs/**"};

    private final ProblemDetailSecurityHandler problemHandler = new ProblemDetailSecurityHandler();

    @Bean
    @Order(1)
    SecurityFilterChain docsFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher(DOCS_PATHS)
            .authorizeHttpRequests(authz -> authz.anyRequest().permitAll())
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .headers(headers -> commonHeaders(headers.contentSecurityPolicy(csp -> csp.policyDirectives(DOCS_CSP))));
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain apiFilterChain(HttpSecurity http, JwtAuthenticationConverter jwtAuthenticationConverter) throws Exception {
        http
            .authorizeHttpRequests(authz -> authz
                // Only the health endpoint is public; any other actuator endpoint requires authentication
                .requestMatchers(HttpMethod.GET, "/actuator/health", "/actuator/health/**").permitAll()
                .requestMatchers(HttpMethod.GET, "/").permitAll()
                // Defense in depth: user management is checked before the body is even parsed or validated
                // (@PreAuthorize runs after @Valid, which would leak validation rules to non-admins)
                .requestMatchers("/api/users", "/api/users/**").hasRole("ADMIN")
                .anyRequest().authenticated())
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter))
                .authenticationEntryPoint(problemHandler)
                .accessDeniedHandler(problemHandler))
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(problemHandler)
                .accessDeniedHandler(problemHandler))
            // Bearer tokens are not sent automatically by browsers, so CSRF does not apply
            .csrf(AbstractHttpConfigurer::disable)
            // CorsFilter runs before authorization, so preflight requests are answered without a token
            .cors(Customizer.withDefaults())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .headers(headers -> commonHeaders(headers.contentSecurityPolicy(csp -> csp.policyDirectives(API_CSP))));
        return http.build();
    }

    private static void commonHeaders(HeadersConfigurer<HttpSecurity> headers) {
        headers
            .contentTypeOptions(Customizer.withDefaults())
            .frameOptions(frame -> frame.deny())
            .referrerPolicy(referrer -> referrer.policy(ReferrerPolicy.NO_REFERRER))
            // Sent only on HTTPS requests, as the HSTS specification requires
            .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(HSTS_MAX_AGE_SECONDS));
    }

    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new KeycloakRealmRoleConverter());
        converter.setPrincipalClaimName("preferred_username");
        return converter;
    }

    /**
     * Strict CORS: only the origins listed in {@code petclinic.cors.allowed-origins} may call the API
     * from a browser. The default is an empty list, which blocks every cross-origin request.
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource(@Value("${petclinic.cors.allowed-origins:}") List<String> allowedOrigins) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(allowedOrigins.stream().map(String::trim).filter(origin -> !origin.isEmpty()).toList());
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        config.setExposedHeaders(List.of("Location", "errors"));
        config.setAllowCredentials(false);
        config.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);
        return source;
    }
}
