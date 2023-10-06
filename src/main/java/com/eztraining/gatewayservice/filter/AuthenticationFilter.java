package com.eztraining.gatewayservice.filter;


import com.eztraining.gatewayservice.util.JwtUtils;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import javax.print.DocFlavor;
import java.util.List;
import java.util.Objects;


@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    @Autowired
    private RouteValidator validator;

    @Autowired
    private JwtUtils jwtUtils;

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        System.out.println("Gateway is hit");
        return ((exchange, chain) -> {
            System.out.println("inside lambda 1");
            //if (validator.isSecured.test(exchange.getRequest())) {
            if (true) {
                //header contains token or not
                System.out.println("inside lambda 2");
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    throw new RuntimeException("missing authorization header");
                }
                System.out.println("authorization header is present");
                //check if Authorization values is not null/empty
                List<String> authHeaderValues = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION);
                String authHeader = null;
                if (authHeaderValues != null && !authHeaderValues.isEmpty()) {
                    authHeader = authHeaderValues.get(0);
                }

                //try to get and validate bearer token
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    authHeader = authHeader.substring(7);
                }
                try {
                    Claims claims = jwtUtils.getClaims(authHeader);
                    String roles = claims.get("roles", String.class);
                    //"[ROLE_ADMIN, ROLE_INSTRUCTOR]"
                    roles = roles.substring(1, roles.length()-1).replaceAll("\\s+", "");;
                    int userId = claims.get("userid", Integer.class);
                    // Add userId and roles to headers
                    ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                            .header("userid", String.valueOf(userId))
                            .header("roles", roles)
                            .build();

                    // Pass the modified request to the next filter in the chain
                    return chain.filter(exchange.mutate().request(modifiedRequest).build());

                } catch (Exception e) {
                    System.out.println("invalid access...!");
                    throw new RuntimeException("un authorized access to application");
                }
            }
            return chain.filter(exchange);
        });
    }

    public static class Config {

    }
}
