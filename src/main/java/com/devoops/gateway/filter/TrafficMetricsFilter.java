package com.devoops.gateway.filter;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class TrafficMetricsFilter extends OncePerRequestFilter {

    private final Counter requestBytesCounter;
    private final Counter responseBytesCounter;

    public TrafficMetricsFilter(MeterRegistry registry) {
        this.requestBytesCounter = Counter.builder("http_traffic_bytes_request_total")
                .description("Total bytes received in HTTP requests")
                .register(registry);
        this.responseBytesCounter = Counter.builder("http_traffic_bytes_response_total")
                .description("Total bytes sent in HTTP responses")
                .register(registry);
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        ContentCachingRequestWrapper wrappedRequest = new ContentCachingRequestWrapper(request, 10 * 1024 * 1024);
        ContentCachingResponseWrapper wrappedResponse = new ContentCachingResponseWrapper(response);

        try {
            filterChain.doFilter(wrappedRequest, wrappedResponse);
        } finally {
            long requestBytes = wrappedRequest.getContentLength();
            if (requestBytes < 0) {
                requestBytes = wrappedRequest.getContentAsByteArray().length;
            }
            requestBytesCounter.increment(requestBytes);

            long responseBytes = wrappedResponse.getContentSize();
            responseBytesCounter.increment(responseBytes);

            wrappedResponse.copyBodyToResponse();
        }
    }
}