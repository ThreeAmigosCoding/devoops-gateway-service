package com.devoops.gateway.filter;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class UniqueVisitorFilter extends OncePerRequestFilter {

    private final MeterRegistry registry;

    public UniqueVisitorFilter(MeterRegistry registry) {
        this.registry = registry;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String ip = extractClientIp(request);
        String userAgent = request.getHeader("User-Agent");
        String visitorHash = computeHash(ip, userAgent);

        Counter.builder("http_visitor_request_total")
                .description("HTTP requests with visitor fingerprint")
                .tag("visitor_hash", visitorHash)
                .register(registry)
                .increment();

        filterChain.doFilter(request, response);
    }

    private String extractClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isEmpty()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private String computeHash(String ip, String userAgent) {
        String input = ip + "|" + (userAgent != null ? userAgent : "unknown");
        return Integer.toHexString(input.hashCode());
    }
}