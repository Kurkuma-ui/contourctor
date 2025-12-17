package com.vadlap.shopAuthorization;

import com.vadlap.shopAuthorization.Data.Role;
import com.vadlap.shopAuthorization.Data.User;
import com.vadlap.shopAuthorization.Data.UserRepository;
import com.vadlap.shopAuthorization.Security.JwtUtil;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthService(UserRepository userRepository,
                       JwtUtil jwtUtil,
                       PasswordEncoder passwordEncoder,
                       AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }
    public String register(String username, String password, String fullname, String email) {
        if (userRepository.findByUsername(username).isPresent())
            throw new RuntimeException("User already exists");

        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole(Role.USER);
        user.setFullname(fullname);
        user.setEmail(email);
        user.setIsAccountLocked(false);
        userRepository.save(user);

        return jwtUtil.generateToken(username, user.getRole());
    }

    public String login(String username, String password) {

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );
        } catch (Exception e) {

            throw new RuntimeException("Invalid username or password");
        }

        // Если мы дошли сюда, аутентификация прошла успешно
        // Нам все еще нужно получить пользователя, чтобы узнать его роль
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found after authentication"));

        return jwtUtil.generateToken(username, user.getRole());
    }
}