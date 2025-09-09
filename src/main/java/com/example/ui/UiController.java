package com.example.ui;

import com.example.dto.LoginRequestDto;
import com.example.dto.RegisterRequestDto;
import com.example.dto.RefreshRequestDto;
import com.example.entity.RefreshToken;
import com.example.entity.User;
import com.example.security.JwtUtils;
import com.example.service.RefreshTokenService;
import com.example.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.time.Duration;
import java.util.Optional;

@Controller
@RequestMapping("/ui")
@RequiredArgsConstructor
public class UiController {

    private final UserService userService;
    private final AuthenticationManager authManager;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;

    private static final String REFRESH_COOKIE_NAME = "refreshToken";

    @GetMapping("/register")
    public String registerForm(Model model) {
        model.addAttribute("register", new RegisterRequestDto());
        return "register";
    }

    @PostMapping("/register")
    public String doRegister(@Valid @ModelAttribute("register") RegisterRequestDto dto,
                             BindingResult br,
                             RedirectAttributes redirectAttributes) {
        if (br.hasErrors()) {
            return "register";
        }
        try {
            User user = userService.register(dto.getUsername(), dto.getEmail(), dto.getPassword());
            redirectAttributes.addFlashAttribute("successMessage", "Registered: " + user.getEmail() + ". Please login.");
            return "redirect:/ui/login";
        } catch (RuntimeException ex) {
            br.reject("registration.error", ex.getMessage());
            return "register";
        }
    }

    @GetMapping("/login")
    public String loginForm(Model model, @ModelAttribute("successMessage") String successMessage) {
        model.addAttribute("login", new LoginRequestDto());
        if (successMessage != null && !successMessage.isEmpty()) {
            model.addAttribute("successMessage", successMessage);
        }
        return "login";
    }

    @PostMapping("/login")
    public String doLogin(@Valid @ModelAttribute("login") LoginRequestDto dto,
                          BindingResult br,
                          HttpServletResponse response,
                          HttpServletRequest request,
                          RedirectAttributes redirectAttributes) {

        if (br.hasErrors()) {
            return "login";
        }

        try {
            Authentication authentication = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(dto.getUsernameOrEmail(), dto.getPassword())
            );

            String username = authentication.getName();
            request.getSession(true).setAttribute("userEmail", username);

            Optional<User> userOpt = userService.findByEmail(username);
            if (userOpt.isEmpty()) {
                redirectAttributes.addFlashAttribute("errorMessage", "User not found after authentication");
                return "redirect:/ui/login";
            }
            User user = userOpt.get();

            String userAgent = request.getHeader("User-Agent");
            RefreshToken rt = refreshTokenService.createRefreshToken(user, userAgent);
            Cookie cookie = new Cookie(REFRESH_COOKIE_NAME, rt.getToken());
            cookie.setHttpOnly(true);
            cookie.setSecure(false);
            cookie.setPath("/");
            cookie.setMaxAge((int) (refreshTokenService.getRefreshTokenDurationMs() / 1000));
            response.addCookie(cookie);

            return "redirect:/ui/me";
        } catch (AuthenticationException ex) {
            br.reject("login.error", "Invalid username/email or password");
            return "login";
        } catch (RuntimeException ex) {
            br.reject("login.error", ex.getMessage());
            return "login";
        }
    }

    @GetMapping("/me")
    public String me(Model model, HttpServletRequest request, RedirectAttributes redirectAttributes) {
        Object email = request.getSession().getAttribute("userEmail");
        if (email == null) {
            redirectAttributes.addFlashAttribute("errorMessage", "Please login");
            return "redirect:/ui/login";
        }
        String userEmail = email.toString();
        userService.findByEmail(userEmail).ifPresent(u -> {
            model.addAttribute("user", u);
        });
        return "profile";
    }

    @PostMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response, RedirectAttributes redirectAttributes) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie c : cookies) {
                if (REFRESH_COOKIE_NAME.equals(c.getName())) {
                    String token = c.getValue();
                    refreshTokenService.findByToken(token).ifPresent(rt -> refreshTokenService.deleteByUser(rt.getUser()));
                    Cookie del = new Cookie(REFRESH_COOKIE_NAME, "");
                    del.setPath("/");
                    del.setHttpOnly(true);
                    del.setMaxAge(0);
                    response.addCookie(del);
                }
            }
        }
        request.getSession().invalidate();
        redirectAttributes.addFlashAttribute("successMessage", "Logged out");
        return "redirect:/ui/login";
    }

    @GetMapping("/")
    public String root() {
        return "redirect:/ui/login";
    }
}
