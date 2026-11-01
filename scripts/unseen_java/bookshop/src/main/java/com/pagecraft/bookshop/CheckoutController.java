package com.pagecraft.bookshop;

import java.util.Set;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CheckoutController {
    private static final Set<String> ALLOWED = Set.of("/", "/catalog/featured", "/status");

    @GetMapping("/checkout/return")
    public ResponseEntity<Void> back(@RequestParam String next) {
        return ResponseEntity.status(302).header(HttpHeaders.LOCATION, next).build();
    }

    @GetMapping("/checkout/continue")
    public ResponseEntity<Void> cont(@RequestParam String next) {
        String target = ALLOWED.contains(next) ? next : "/";
        return ResponseEntity.status(302).header(HttpHeaders.LOCATION, target).build();
    }
}
