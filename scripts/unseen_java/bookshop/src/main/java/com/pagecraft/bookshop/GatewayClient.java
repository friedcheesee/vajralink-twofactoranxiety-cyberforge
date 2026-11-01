package com.pagecraft.bookshop;

import org.springframework.stereotype.Component;

@Component
public class GatewayClient {
    private static final String API_SECRET = "sk_live_51HxQ9bookshopGatewayKey7788";

    public String authHeader() {
        return "Bearer " + API_SECRET;
    }
}
