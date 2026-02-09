package com.devoops.gateway.config;

import io.micrometer.common.KeyValue;
import io.micrometer.common.KeyValues;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.observation.DefaultServerRequestObservationConvention;
import org.springframework.http.server.observation.ServerRequestObservationContext;
import org.springframework.http.server.observation.ServerRequestObservationConvention;

import java.util.stream.StreamSupport;

@Configuration
public class MetricsConfig {

    @Bean
    public ServerRequestObservationConvention serverRequestObservationConvention() {
        return new DefaultServerRequestObservationConvention() {
            @Override
            @NonNull
            public KeyValues getLowCardinalityKeyValues(@NonNull ServerRequestObservationContext context) {
                KeyValues keyValues = super.getLowCardinalityKeyValues(context);

                HttpServletResponse response = context.getResponse();
                if (response != null && response.getStatus() == 404) {
                    HttpServletRequest request = context.getCarrier();
                    assert request != null;
                    String originalUri = request.getRequestURI();

                    KeyValues filtered = KeyValues.of(
                        StreamSupport.stream(keyValues.spliterator(), false)
                            .filter(kv -> !"uri".equals(kv.getKey()))
                            .toArray(KeyValue[]::new)
                    );
                    keyValues = filtered.and(KeyValue.of("uri", originalUri));
                }

                return keyValues;
            }
        };
    }
}
