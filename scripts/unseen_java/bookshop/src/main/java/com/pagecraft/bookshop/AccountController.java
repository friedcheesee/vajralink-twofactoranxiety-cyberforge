package com.pagecraft.bookshop;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AccountController {
    private static final String AVATAR_DIR = "/tmp/avatars";

    @GetMapping("/account/avatar")
    public String avatar(@RequestParam String name) throws Exception {
        Path p = Paths.get(AVATAR_DIR + "/" + name);
        return Files.readString(p);
    }
}
