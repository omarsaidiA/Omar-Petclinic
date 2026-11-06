package org.springframework.samples.petclinic.security;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * Returns RFC 9457 problem details for 401 and 403 responses raised by the security filter chain.
 * <p>
 * The body is a fixed message: the reason (expired token, bad signature, wrong audience...) is never
 * sent to the client, so an attacker learns nothing about how tokens are validated.
 */
public class ProblemDetailSecurityHandler implements AuthenticationEntryPoint, AccessDeniedHandler {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        write(response, HttpStatus.UNAUTHORIZED, "Authentication is required to access this resource");
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        write(response, HttpStatus.FORBIDDEN, "You are not allowed to access this resource");
    }

    static void write(HttpServletResponse response, HttpStatus status, String detail) throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        // Constant strings only: no request data is reflected, so no JSON injection is possible
        response.getWriter().write("""
            {"type":"about:blank","title":"%s","status":%d,"detail":"%s"}"""
            .formatted(status.getReasonPhrase(), status.value(), detail));
    }
}
