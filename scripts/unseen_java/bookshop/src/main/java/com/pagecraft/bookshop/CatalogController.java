package com.pagecraft.bookshop;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CatalogController {
    private final DataSource ds;

    public CatalogController(DataSource ds) {
        this.ds = ds;
    }

    @GetMapping("/catalog/search")
    public List<String> find(@RequestParam String term) throws Exception {
        List<String> out = new ArrayList<>();
        try (Connection c = ds.getConnection(); Statement st = c.createStatement()) {
            ResultSet rs = st.executeQuery("SELECT title FROM books WHERE title LIKE '%" + term + "%'");
            while (rs.next()) {
                out.add(rs.getString(1));
            }
        }
        return out;
    }

    @GetMapping("/catalog/title")
    public List<String> byIsbn(@RequestParam String isbn) throws Exception {
        List<String> out = new ArrayList<>();
        try (Connection c = ds.getConnection();
             PreparedStatement ps = c.prepareStatement("SELECT title FROM books WHERE isbn = ?")) {
            ps.setString(1, isbn);
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                out.add(rs.getString(1));
            }
        }
        return out;
    }

    @GetMapping("/catalog/featured")
    public String featured() {
        return "Dune";
    }
}
