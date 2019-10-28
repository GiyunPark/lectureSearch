package com.lecturesearch.lecture.user;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpSession;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String login(){
        return "/user/login";
    }

    @GetMapping(value= "/loginSuccess")
    public String loginComplete(HttpSession session){

        // SecurityContextHolder에서 인증된 정보를 OAuth2Authentication 형태로 가져온다.
        OAuth2Authentication authentication = (OAuth2Authentication)
                SecurityContextHolder.getContext().getAuthentication();

        // 개인정보를 Map으로 가져온다.
        Map<String, String> map = (HashMap<String, String>)
                authentication.getUserAuthentication().getDetails();

        // 인증된 정보를 User에 객체로 변환하여 저장
        session.setAttribute("user", User.builder()
                .name(map.get("name"))
                .email(map.get("email"))
                .principal(map.get("principal"))
                .socialType(SocialType.FACEBOOK)
                .createdDate(LocalDateTime.now())
                .build()
        );

        return "redirect/main";
    }
}
