package org.springframework.samples.petclinic.security;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Security audit log, written to a dedicated {@code SECURITY} logger so it can be routed to a SIEM.
 * <p>
 * What is logged: event type, HTTP method, path, client IP, user name and the failure category.
 * What is never logged: tokens, Authorization headers, query strings or request bodies (they may hold
 * personal data or credentials). Values are stripped of CR/LF to prevent log injection (CWE-117).
 */
public final class SecurityEventLogger {

    private static final Logger SECURITY = LoggerFactory.getLogger("SECURITY");
    private static final int MAX_VALUE_LENGTH = 200;

    private SecurityEventLogger() {
    }

    public static void authenticationFailure(HttpServletRequest request, Exception reason) {
        SECURITY.warn("event=authentication_failure method={} path={} ip={} reason={}",
            request.getMethod(), sanitize(request.getRequestURI()), request.getRemoteAddr(),
            reason == null ? "unknown" : reason.getClass().getSimpleName());
    }

    public static void accessDenied(HttpServletRequest request) {
        SECURITY.warn("event=access_denied method={} path={} ip={} user={}",
            request.getMethod(), sanitize(request.getRequestURI()), request.getRemoteAddr(), currentUser());
    }

    public static void rateLimited(HttpServletRequest request, String clientKey) {
        SECURITY.warn("event=rate_limited method={} path={} ip={} client={}",
            request.getMethod(), sanitize(request.getRequestURI()), request.getRemoteAddr(), sanitize(clientKey));
    }

    private static String currentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication == null ? "anonymous" : sanitize(authentication.getName());
    }

    static String sanitize(String value) {
        if (value == null) {
            return "-";
        }
        String clean = value.replaceAll("[\\r\\n\\t]", "_");
        return clean.length() > MAX_VALUE_LENGTH ? clean.substring(0, MAX_VALUE_LENGTH) + "..." : clean;
    }
}
