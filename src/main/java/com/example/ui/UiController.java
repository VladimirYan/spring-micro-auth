package com.example.ui;

import com.example.dto.*;
import com.example.entity.*;
import com.example.repository.*;
import com.example.service.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/ui")
@RequiredArgsConstructor
public class UiController {

    private final UserService userService;
    private final AuthenticationManager authManager;
    private final RefreshTokenService refreshTokenService;
    private final PasswordResetService passwordResetService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

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
        userService.findByEmail(userEmail).ifPresent(u -> model.addAttribute("user", u));
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

    @GetMapping("/change-password")
    public String changePasswordForm(Model model) {
        model.addAttribute("changePassword", new ChangePasswordDto());
        return "change-password";
    }

    @PostMapping("/change-password")
    public String doChangePassword(@Valid @ModelAttribute("changePassword") ChangePasswordDto dto,
                                   BindingResult br,
                                   HttpServletRequest request,
                                   RedirectAttributes redirectAttributes) {
        if (br.hasErrors()) {
            return "change-password";
        }
        Object email = request.getSession().getAttribute("userEmail");
        if (email == null) {
            redirectAttributes.addFlashAttribute("errorMessage", "Please login");
            return "redirect:/ui/login";
        }
        User user = userService.findByEmail(email.toString())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(dto.getOldPassword(), user.getPassword())) {
            br.rejectValue("oldPassword", "oldPassword.invalid", "Old password is incorrect");
            return "change-password";
        }

        user.setPassword(passwordEncoder.encode(dto.getNewPassword()));
        userService.save(user);
        refreshTokenService.deleteByUser(user);

        redirectAttributes.addFlashAttribute("successMessage", "Password changed");
        return "redirect:/ui/me";
    }

    @GetMapping("/forgot-password")
    public String forgotPasswordForm(Model model) {
        model.addAttribute("forgotPassword", new ForgotPasswordDto());
        return "forgot-password";
    }

    @PostMapping("/forgot-password")
    public String doForgotPassword(@Valid @ModelAttribute("forgotPassword") ForgotPasswordDto dto,
                                   BindingResult br,
                                   RedirectAttributes redirectAttributes) {
        if (br.hasErrors()) {
            return "forgot-password";
        }
        try {
            String token = passwordResetService.createTokenForEmail(dto.getEmail());
            redirectAttributes.addFlashAttribute("successMessage", "Password reset token created (demo): " + token);
            return "redirect:/ui/login";
        } catch (RuntimeException ex) {
            br.reject("forgot.error", ex.getMessage());
            return "forgot-password";
        }
    }

    @GetMapping("/reset-password")
    public String resetPasswordForm(@RequestParam(value = "token", required = false) String token, Model model) {
        ResetPasswordDto dto = new ResetPasswordDto();
        dto.setToken(token);
        model.addAttribute("resetPassword", dto);
        return "reset-password";
    }

    @PostMapping("/reset-password")
    public String doResetPassword(@Valid @ModelAttribute("resetPassword") ResetPasswordDto dto,
                                  BindingResult br,
                                  RedirectAttributes redirectAttributes) {
        if (br.hasErrors()) {
            return "reset-password";
        }
        try {
            User user = passwordResetService.validateTokenAndGetUser(dto.getToken());
            user.setPassword(passwordEncoder.encode(dto.getNewPassword()));
            userService.save(user);
            passwordResetService.removeTokensForUser(user);
            refreshTokenService.deleteByUser(user);
            redirectAttributes.addFlashAttribute("successMessage", "Password reset. Please login.");
            return "redirect:/ui/login";
        } catch (RuntimeException ex) {
            br.reject("reset.error", ex.getMessage());
            return "reset-password";
        }
    }

    @GetMapping("/sessions")
    public String sessions(Model model, HttpServletRequest request, RedirectAttributes redirectAttributes) {
        Object email = request.getSession().getAttribute("userEmail");
        if (email == null) {
            redirectAttributes.addFlashAttribute("errorMessage", "Please login");
            return "redirect:/ui/login";
        }
        User user = userService.findByEmail(email.toString()).orElseThrow(() -> new RuntimeException("User not found"));
        List<Map<String, Object>> sessions = refreshTokenService.findAllByUser(user).stream().map(rt -> {
            Map<String, Object> m = new HashMap<>();
            m.put("id", rt.getId());
            String preview = null;
            if (rt.getToken() != null) {
                int len = Math.min(8, rt.getToken().length());
                preview = rt.getToken().substring(0, len) + "...";
            }
            m.put("tokenPreview", preview);
            m.put("fullToken", rt.getToken());
            m.put("expiry", rt.getExpiry());
            m.put("deviceInfo", rt.getDeviceInfo() == null ? "unknown" : rt.getDeviceInfo());
            return m;
        }).collect(Collectors.toList());
        model.addAttribute("sessions", sessions);
        return "sessions";
    }

    @PostMapping("/revoke")
    public String revokeSession(@RequestParam("token") String token,
                                HttpServletRequest request,
                                RedirectAttributes redirectAttributes) {
        Object email = request.getSession().getAttribute("userEmail");
        if (email == null) {
            redirectAttributes.addFlashAttribute("errorMessage", "Please login");
            return "redirect:/ui/login";
        }
        refreshTokenRepository.findByToken(token).ifPresent(refreshTokenRepository::delete);
        redirectAttributes.addFlashAttribute("successMessage", "Session revoked");
        return "redirect:/ui/sessions";
    }

    @GetMapping("/admin/users")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminUsers(Model model) {
        List<User> users = userRepository.findAll();
        model.addAttribute("users", users);
        return "admin-users";
    }

    @PostMapping("/admin/users/{id}/toggle")
    @PreAuthorize("hasRole('ADMIN')")
    public String toggleUserEnabled(@PathVariable("id") Long id, RedirectAttributes redirectAttributes) {
        User u = userRepository.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
        u.setEnabled(!Boolean.TRUE.equals(u.isEnabled()));
        userRepository.save(u);
        redirectAttributes.addFlashAttribute("successMessage", "User updated");
        return "redirect:/ui/admin/users";
    }

    @GetMapping("/mfa/setup")
    public String mfaSetup(Model model, HttpServletRequest request, RedirectAttributes redirectAttributes) {
        Object email = request.getSession().getAttribute("userEmail");
        if (email == null) {
            redirectAttributes.addFlashAttribute("errorMessage", "Please login");
            return "redirect:/ui/login";
        }

        byte[] bytes = new byte[10];
        new SecureRandom().nextBytes(bytes);
        String secret = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        String account = email.toString();
        String issuer = "AuthService";
        String otpauth = String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s", issuer, account, secret, issuer);

        model.addAttribute("qrCodeUrl", null);
        model.addAttribute("secret", secret);
        model.addAttribute("otpauth", otpauth);
        return "mfa-setup";
    }

    @PostMapping("/mfa/verify")
    public String mfaVerify(@RequestParam("code") String code,
                            HttpServletRequest request,
                            RedirectAttributes redirectAttributes) {
        redirectAttributes.addFlashAttribute("successMessage", "MFA verification is demo-only and not implemented.");
        return "redirect:/ui/me";
    }

    @GetMapping("/")
    public String root() {
        return "redirect:/ui/login";
    }
}
