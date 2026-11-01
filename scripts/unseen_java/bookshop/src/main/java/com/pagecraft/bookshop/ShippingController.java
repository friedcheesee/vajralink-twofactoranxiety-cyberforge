package com.pagecraft.bookshop;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ShippingController {
    public static class TraceRequest {
        public String host;
    }

    @PostMapping("/api/shipping/trace")
    public String trace(@RequestBody TraceRequest req) throws Exception {
        Process p = Runtime.getRuntime().exec(new String[] {"sh", "-c", "ping -c 1 " + req.host});
        StringBuilder sb = new StringBuilder();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line).append('\n');
            }
        }
        return sb.toString();
    }
}
