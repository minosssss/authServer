package com.example.authserver.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String getLoginPage() {
        return "login";  // login.html 템플릿 파일 반환
    }

    @GetMapping("/register")
    public String getRegisterPage() {
        return "register";  // register.html 템플릿 파일 반환
    }

    @GetMapping("/protected")
    public String getRegisterPage2(@AuthenticationPrincipal OAuth2User user, @RegisteredOAuth2AuthorizedClient("microsoft") OAuth2AuthorizedClient authorizedClient) {
        System.out.println(user);
        return "안녕";  // register.html 템플릿 파일 반환
    }
}