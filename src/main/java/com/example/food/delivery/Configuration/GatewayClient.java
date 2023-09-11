package com.example.food.delivery.Configuration;

import com.example.food.delivery.Util.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class GatewayClient {
    @Autowired
    private JwtUtils jwtUtils;

    private Map<String, List<String>> roleEndpointMapping = new HashMap<>();

    public GatewayClient() {
        roleEndpointMapping.put("ADMIN", Arrays.asList("add/admin", "/getRestaurants", "/approve/restaurant"));
        roleEndpointMapping.put("CO_ADMIN", Arrays.asList("/approve/restaurant", "/restaurants/updateRestaurant"));
        roleEndpointMapping.put("SUPER_ADMIN", Arrays.asList("user/transfer-super-admin", "/approve/restaurant"));
        roleEndpointMapping.put("CUSTOMER", Arrays.asList("/orders/getOrder"));
        roleEndpointMapping.put("REST_AGENT", Arrays.asList("/restaurants/getRestaurant"));
    }

    public boolean hasAccessToEndpoint(String jwtToken, String endpoint) {
        String role = jwtUtils.extractRoleFromToken(jwtToken);
        List<String> allowedEndpoints = roleEndpointMapping.get(role);
        return allowedEndpoints != null && allowedEndpoints.stream().anyMatch(url -> endpoint.contains(url));
    }
}
