package com.devoops.gateway.filter;

import com.devoops.gateway.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private record PublicEndpoint(String pattern, HttpMethod... methods) {
        boolean matchesMethod(String method) {
            if (methods.length == 0) {
                return true; // No method restriction = all methods allowed
            }
            return Arrays.stream(methods).anyMatch(m -> m.name().equalsIgnoreCase(method));
        }
    }

    private static final List<PublicEndpoint> PUBLIC_ENDPOINTS = List.of(
            // Auth endpoints - all methods
            new PublicEndpoint("/api/user/auth/**"),
            new PublicEndpoint("/api/user/test"),
            new PublicEndpoint("/actuator/**"),
            // Accommodation endpoints - GET only
            new PublicEndpoint("/api/accommodation", HttpMethod.GET),
            new PublicEndpoint("/api/accommodation/*", HttpMethod.GET),
            new PublicEndpoint("/api/accommodation/host/*", HttpMethod.GET),
            new PublicEndpoint("/api/accommodation/*/photos", HttpMethod.GET),
            new PublicEndpoint("/api/accommodation/*/photos/*", HttpMethod.GET),
            // Availability endpoints - GET only
            new PublicEndpoint("/api/accommodation/*/availability", HttpMethod.GET),
            new PublicEndpoint("/api/accommodation/*/availability/*", HttpMethod.GET),
            // Rating endpoints - GET only
            new PublicEndpoint("/api/rating", HttpMethod.GET),
            new PublicEndpoint("/api/rating/target/*", HttpMethod.GET)
    );

    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();
        String method = request.getMethod();

        if (isPublicEndpoint(path, method)) {
            filterChain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            sendError(response, "Missing or invalid Authorization header");
            return;
        }

        try {
            String token = authHeader.substring(7);
            Claims claims = jwtService.parseToken(token);

            String userId = jwtService.getUserId(claims);
            String role = jwtService.getRole(claims);

            if (userId == null || role == null) {
                sendError(response, "Invalid token claims");
                return;
            }

            HttpServletRequest wrappedRequest = new HeaderAddingRequestWrapper(request, Map.of(
                    "X-User-Id", userId,
                    "X-User-Role", role
            ));

            filterChain.doFilter(wrappedRequest, response);
        } catch (JwtException e) {
            sendError(response, "Invalid or expired token");
        }
    }

    private boolean isPublicEndpoint(String path, String method) {
        return PUBLIC_ENDPOINTS.stream()
                .anyMatch(endpoint ->
                        pathMatcher.match(endpoint.pattern(), path) && endpoint.matchesMethod(method));
    }

    private void sendError(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");
        response.getWriter().write("{\"status\":401,\"detail\":\"%s\"}".formatted(message));
    }

    private static class HeaderAddingRequestWrapper extends HttpServletRequestWrapper {
        private final Map<String, String> extraHeaders;

        public HeaderAddingRequestWrapper(HttpServletRequest request, Map<String, String> extraHeaders) {
            super(request);
            this.extraHeaders = extraHeaders;
        }

        @Override
        public String getHeader(String name) {
            if (extraHeaders.containsKey(name)) {
                return extraHeaders.get(name);
            }
            return super.getHeader(name);
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            if (extraHeaders.containsKey(name)) {
                return Collections.enumeration(List.of(extraHeaders.get(name)));
            }
            return super.getHeaders(name);
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            Set<String> names = new LinkedHashSet<>();
            Enumeration<String> original = super.getHeaderNames();
            while (original.hasMoreElements()) {
                names.add(original.nextElement());
            }
            names.addAll(extraHeaders.keySet());
            return Collections.enumeration(names);
        }
    }
}
