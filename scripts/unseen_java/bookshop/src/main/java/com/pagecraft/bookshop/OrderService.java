package com.pagecraft.bookshop;

import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class OrderService {
    private final JdbcTemplate jdbc;

    public OrderService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<Map<String, Object>> load(String orderId) {
        String sql = "SELECT * FROM orders WHERE id = '" + orderId + "'";
        return jdbc.queryForList(sql);
    }
}
