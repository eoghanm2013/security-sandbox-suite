package com.petshop;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Base64;
import java.util.List;
import java.util.Map;

@Controller
public class PetShopController {

    // SAST findings: hardcoded credentials
    private static final String SECRET_KEY = "BITS_AND_BYTES_SUPER_SECRET_KEY_2024";
    private static final String INTERNAL_API_TOKEN = "sk_live_dd_internal_api_token_never_commit";

    private static final String TRACER = "dd-java-agent";
    private static final String VERSION = "latest";

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @PostConstruct
    public void init() {
        try {
            Files.createDirectories(Path.of("/tmp/uploads"));
        } catch (Exception ignored) {
        }
    }

    private void addTracerAttrs(Model model) {
        model.addAttribute("tracer", TRACER);
        model.addAttribute("version", VERSION);
    }

    private String getPrefix(HttpServletRequest request) {
        String prefix = request.getHeader("X-Forwarded-Prefix");
        return prefix != null ? prefix : "";
    }

    private void addCommonAttrs(Model model, HttpServletRequest request) {
        addTracerAttrs(model);
        model.addAttribute("prefix", getPrefix(request));
    }

    @GetMapping("/")
    public String index(Model model, HttpServletRequest request) {
        List<Map<String, Object>> products = jdbcTemplate.queryForList("SELECT * FROM products ORDER BY id");
        model.addAttribute("products", products);
        addCommonAttrs(model, request);
        return "index";
    }

    @GetMapping("/search")
    public String search(@RequestParam(value = "q", defaultValue = "") String q, Model model, HttpServletRequest request) {
        List<Map<String, Object>> results = List.of();
        String error = null;
        if (!q.isEmpty()) {
            // VULNERABLE: SQL Injection via string concatenation
            String sql = "SELECT * FROM products WHERE name ILIKE '%" + q + "%' OR description ILIKE '%" + q + "%'";
            try {
                results = jdbcTemplate.queryForList(sql);
            } catch (Exception e) {
                error = e.getMessage();
            }
        }
        model.addAttribute("q", q);
        model.addAttribute("results", results);
        model.addAttribute("error", error);
        addCommonAttrs(model, request);
        return "search";
    }

    @GetMapping("/login")
    public String loginForm(Model model, HttpServletRequest request) {
        model.addAttribute("error", (String) null);
        addCommonAttrs(model, request);
        return "login";
    }

    @PostMapping("/login")
    public String login(@RequestParam("username") String username,
                        @RequestParam("password") String password,
                        HttpSession session,
                        Model model,
                        HttpServletRequest request) {
        String prefix = getPrefix(request);
        // VULNERABLE: SQL Injection via string concatenation
        String sql = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
        try {
            List<Map<String, Object>> rows = jdbcTemplate.queryForList(sql);
            if (!rows.isEmpty()) {
                Map<String, Object> user = rows.get(0);
                session.setAttribute("user", user.get("username"));
                session.setAttribute("role", user.get("role"));
                return "redirect:" + prefix + "/";
            }
        } catch (Exception ignored) {
        }
        model.addAttribute("error", "Invalid username or password");
        addCommonAttrs(model, request);
        return "login";
    }

    @GetMapping("/logout")
    public String logout(HttpSession session, HttpServletRequest request) {
        session.invalidate();
        return "redirect:" + getPrefix(request) + "/";
    }

    @GetMapping("/product/{id}")
    public String product(@PathVariable String id, HttpSession session, HttpServletRequest request, HttpServletResponse response, Model model) {
        // VULNERABLE: SQL Injection (numeric)
        String sql = "SELECT * FROM products WHERE id = " + id;
        try {
            List<Map<String, Object>> rows = jdbcTemplate.queryForList(sql);
            if (rows.isEmpty()) {
                response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                model.addAttribute("error", "Product not found");
                addCommonAttrs(model, request);
                return "error";
            }
            Map<String, Object> product = rows.get(0);
            List<Map<String, Object>> reviews = jdbcTemplate.queryForList(
                    "SELECT * FROM reviews WHERE product_id = ? ORDER BY created_at DESC",
                    product.get("id"));
            model.addAttribute("product", product);
            model.addAttribute("reviews", reviews);
            model.addAttribute("sessionUser", session.getAttribute("user") != null ? session.getAttribute("user").toString() : "");
            addCommonAttrs(model, request);
            return "product";
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            model.addAttribute("error", e.getMessage());
            addCommonAttrs(model, request);
            return "error";
        }
    }

    @PostMapping("/review")
    public String addReview(@RequestParam("product_id") String productId,
                            @RequestParam(value = "username", defaultValue = "anonymous") String username,
                            @RequestParam(value = "rating", defaultValue = "5") String rating,
                            @RequestParam(value = "body", defaultValue = "") String body,
                            HttpServletRequest request) {
        // VULNERABLE: Stored XSS (body is stored as-is, rendered unescaped in template)
        jdbcTemplate.update(
                "INSERT INTO reviews (product_id, username, rating, body) VALUES (?, ?, ?, ?)",
                Integer.parseInt(productId), username, Integer.parseInt(rating), body);
        return "redirect:" + getPrefix(request) + "/product/" + productId;
    }

    @GetMapping("/profile/{username}")
    public String profile(@PathVariable String username, Model model, HttpServletRequest request) {
        // VULNERABLE: Reflected XSS (username rendered with th:utext)
        Map<String, Object> user = null;
        try {
            List<Map<String, Object>> rows = jdbcTemplate.queryForList("SELECT * FROM users WHERE username = ?", username);
            if (!rows.isEmpty()) {
                user = rows.get(0);
            }
        } catch (Exception ignored) {
        }
        model.addAttribute("username", username);
        model.addAttribute("user", user);
        addCommonAttrs(model, request);
        return "profile";
    }

    @PostMapping("/upload")
    @ResponseBody
    public ResponseEntity<?> upload(@RequestParam("file") MultipartFile file,
                                    @RequestParam(value = "filename", required = false) String filenameParam,
                                    HttpServletRequest request) {
        if (file == null || file.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "No file provided"));
        }
        // VULNERABLE: Path Traversal (user-controlled filename)
        String filename = filenameParam != null ? filenameParam : file.getOriginalFilename();
        if (filename == null) {
            filename = "upload";
        }
        try {
            Path savePath = Paths.get("/tmp/uploads", filename);
            Files.createDirectories(savePath.getParent());
            file.transferTo(savePath.toFile());
            return ResponseEntity.ok(Map.of(
                    "message", "Saved to " + savePath.toString(),
                    "filename", filename));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/webhook")
    @ResponseBody
    public ResponseEntity<?> webhook(HttpServletRequest request) {
        String url = request.getParameter("url");
        if ((url == null || url.isEmpty()) && request.getContentType() != null && request.getContentType().contains("json")) {
            try {
                Map<String, String> body = objectMapper.readValue(request.getInputStream(), new TypeReference<>() {});
                url = body != null ? body.get("url") : null;
            } catch (Exception ignored) {
            }
        }
        if (url == null || url.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "url required"));
        }
        // VULNERABLE: SSRF (fetches arbitrary user-provided URL)
        try {
            URL targetUrl = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) targetUrl.openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setRequestMethod("GET");
            int status = conn.getResponseCode();
            String data = new String(conn.getInputStream().readAllBytes()).replaceAll("[^\\x20-\\x7E]", "?");
            if (data.length() > 2000) {
                data = data.substring(0, 2000);
            }
            return ResponseEntity.ok(Map.of("status", status, "body", data));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/export")
    @ResponseBody
    public ResponseEntity<?> export(@RequestParam(value = "file", required = false) String filename) {
        if (filename == null || filename.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "file parameter required"));
        }
        // VULNERABLE: Command Injection
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", "cat /tmp/uploads/" + filename});
            byte[] output = p.getInputStream().readAllBytes();
            p.waitFor();
            return ResponseEntity.ok()
                    .contentType(MediaType.TEXT_PLAIN)
                    .body(output);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/cart/restore")
    @ResponseBody
    public ResponseEntity<?> cartRestore(HttpServletRequest request) {
        String cartData = request.getParameter("cart_data");
        if ((cartData == null || cartData.isEmpty()) && request.getContentType() != null && request.getContentType().contains("json")) {
            try {
                Map<String, String> body = objectMapper.readValue(request.getInputStream(), new TypeReference<>() {});
                cartData = body != null ? body.get("cart_data") : null;
            } catch (Exception ignored) {
            }
        }
        if (cartData == null || cartData.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "cart_data required"));
        }
        // VULNERABLE: Insecure Deserialization (Java ObjectInputStream)
        try {
            byte[] data = Base64.getDecoder().decode(cartData);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            Object cart = ois.readObject();
            ois.close();
            return ResponseEntity.ok(Map.of("cart", String.valueOf(cart)));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/health")
    @ResponseBody
    public Map<String, String> health() {
        return Map.of(
                "status", "ok",
                "service", "petshop-java",
                "tracer", TRACER);
    }
}
