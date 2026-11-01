package com.pagecraft.bookshop;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StatusController {
    @GetMapping("/status")
    public String status() {
        return "ok";
    }

    @GetMapping("/")
    public String index() {
        return "Pagecraft Books";
    }
}
