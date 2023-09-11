package com.example.food.delivery.JwtFilter;

import com.example.food.delivery.Configuration.GatewayClient;
import com.example.food.delivery.Util.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {
    @Autowired
    private RouteValidator validator;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private GatewayClient gatewayClient;

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (((exchange, chain) -> {
            ServerHttpRequest request = null;
            if (validator.isSecured.test(exchange.getRequest())) {
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    throw new RuntimeException("Missing authorization header");
                }
                String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    authHeader = authHeader.substring(7);
                }
                try {
                    String jwt = jwtUtils.getTokenByUuid(authHeader);
                    jwtUtils.validateJwtToken(jwt);
                    String email = jwtUtils.getUserEmailFromJwtToken(jwt);
                    String role = jwtUtils.extractRoleFromToken(jwt);
                    if (!email.trim().isEmpty() || !role.trim().isEmpty()) {
                        request = exchange.getRequest()
                                .mutate()
                                .header("userEmail", email)
                                .header("userRole", role)
                                .build();
                    } else {
                        throw new RuntimeException("Access Denied");
                    }
                } catch (Exception e) {
                    throw new RuntimeException("un authorized access to application");
                }
            }

            return chain.filter(exchange.mutate().request(request).build());
        }
        ));
    }

    public static class Config {

    }
}
