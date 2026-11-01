package com.pagecraft.bookshop;

import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OrderController {
    private final OrderService orders;

    public OrderController(OrderService orders) {
        this.orders = orders;
    }

    @GetMapping("/api/orders/{orderId}")
    public List<Map<String, Object>> show(@PathVariable String orderId) {
        return orders.load(orderId);
    }
}
