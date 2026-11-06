package org.springframework.samples.petclinic.security;

import java.io.IOException;
import java.time.Duration;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Token-bucket rate limiting (Bucket4j), applied after authentication.
 * <p>
 * Authenticated callers are limited per user, anonymous callers per client IP with a lower limit.
 * The IP is the socket address, not {@code X-Forwarded-For}, which any client can forge.
 * Buckets live in a size-bounded Caffeine cache so an attacker rotating IPs cannot exhaust memory.
 * Over the limit the API answers 429 with a {@code Retry-After} header.
 */
public class RateLimitFilter extends OncePerRequestFilter {

    private static final int MAX_TRACKED_CLIENTS = 100_000;

    private final Cache<String, Bucket> buckets = Caffeine.newBuilder()
        .maximumSize(MAX_TRACKED_CLIENTS)
        .expireAfterAccess(Duration.ofMinutes(10))
        .build();

    private final long authenticatedPerMinute;
    private final long anonymousPerMinute;

    public RateLimitFilter(long authenticatedPerMinute, long anonymousPerMinute) {
        this.authenticatedPerMinute = authenticatedPerMinute;
        this.anonymousPerMinute = anonymousPerMinute;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Orchestrator health probes must never be throttled
        return request.getRequestURI().startsWith(request.getContextPath() + "/actuator/health");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean authenticated = authentication != null && authentication.isAuthenticated()
            && !(authentication instanceof AnonymousAuthenticationToken);
        String key = authenticated ? "user:" + authentication.getName() : "ip:" + request.getRemoteAddr();
        long perMinute = authenticated ? authenticatedPerMinute : anonymousPerMinute;

        Bucket bucket = buckets.get(key, k -> newBucket(perMinute));
        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);
        if (probe.isConsumed()) {
            response.setHeader("X-RateLimit-Remaining", Long.toString(probe.getRemainingTokens()));
            chain.doFilter(request, response);
            return;
        }
        long retryAfterSeconds = Math.max(1, Duration.ofNanos(probe.getNanosToWaitForRefill()).toSeconds());
        SecurityEventLogger.rateLimited(request, key);
        response.setHeader(HttpHeaders.RETRY_AFTER, Long.toString(retryAfterSeconds));
        ProblemDetailSecurityHandler.write(response, HttpStatus.TOO_MANY_REQUESTS, "Too many requests, retry later");
    }

    private static Bucket newBucket(long perMinute) {
        return Bucket.builder()
            .addLimit(Bandwidth.builder().capacity(perMinute).refillGreedy(perMinute, Duration.ofMinutes(1)).build())
            .build();
    }
}
