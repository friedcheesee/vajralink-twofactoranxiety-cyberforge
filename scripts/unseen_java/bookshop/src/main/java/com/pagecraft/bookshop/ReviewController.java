package com.pagecraft.bookshop;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

@RestController
public class ReviewController {
    @GetMapping(value = "/reviews/preview", produces = MediaType.TEXT_HTML_VALUE)
    public String preview(@RequestParam String comment) {
        return "<html><body><h3>Your review</h3><p>" + comment + "</p></body></html>";
    }

    @PostMapping(value = "/feedback/submit", produces = MediaType.TEXT_HTML_VALUE)
    public String submit(@RequestParam String message) {
        return "<html><body>Thanks: " + HtmlUtils.htmlEscape(message) + "</body></html>";
    }
}
