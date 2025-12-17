package com.vadlap.shopAuthorization.Web;

import com.vadlap.shopAuthorization.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.Data;
import org.springframework.web.bind.annotation.PostMapping;
// @RequestBody больше не нужен
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam; // <-- ДОБАВЛЕНО
import org.springframework.web.bind.annotation.RestController;


// DTO (Data Transfer Object) для запросов
// (Этот класс больше не используется контроллером, но может быть полезен в будущем)
@Data
class AuthRequest {
    private String username;
    private String password;
}

// DTO для ответа (содержит только токен)
@Data
class AuthResponse {
    private final String token;
    public AuthResponse(String token) {
        this.token = token;
    }
}


@Tag(name = "Auth", description = "Эндпоинты авторизации и регистрации")
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final AuthService authService;
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @Operation(summary = "Регистрация нового пользователя")
    @PostMapping("/register")
    public AuthResponse register(
            @RequestParam String username,
            @RequestParam String password,
            @RequestParam String fullname,
            @RequestParam String email

    ) {
        String token = authService.register(username, password, fullname, email);
        return new AuthResponse(token);
    }

    @Operation(summary = "Вход в систему (логин)")
    @PostMapping("/login")
    public AuthResponse login(@RequestParam String username, @RequestParam String password) {
        String token = authService.login(username, password);
        return new AuthResponse(token);
    }
}