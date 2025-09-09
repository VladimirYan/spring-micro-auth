package com.example.ui;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

import java.time.Instant;

@ControllerAdvice(assignableTypes = UiController.class)
public class UiControllerAdvice {

    @ModelAttribute
    public void addCommonAttributes(Model model) {
        model.addAttribute("timestamp", Instant.now());
    }
}
