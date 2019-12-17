package com.lecturesearch.lecture.OAuth2.controller;

import com.lecturesearch.lecture.OAuth2.domain.User;
import com.lecturesearch.lecture.OAuth2.annotation.SocialUser;
import com.lecturesearch.lecture.OAuth2.password.PasswordEncoding;
import com.lecturesearch.lecture.OAuth2.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpSession;
import java.util.Optional;


@Controller
public class UserController {

    @Autowired
    private UserService userService;


    @GetMapping("/login")
    public String login(){
        return "form";
    }

    @PostMapping("/loginPass")
    public String loginPass(String email, String password, HttpSession httpSession){
        System.out.println("email :" + email + " password : " + password);
        User user = userService.findByEmail(email).get(); // email로 user조회

        PasswordEncoding passwordEncoding = new PasswordEncoding();

        // 로그인 검증
        if(user==null){
            // user가 존재하지 않는다.
            System.out.println("user가 존재하지않음."); //test
            return "redirect:/login";
        } else if(!passwordEncoding.matches(password, user.getPassword())){
            // email이 존재하지만, 비밀번호가 일치하지 않는다면,
            System.out.println("비밀번호 불일치"); //test
            return "redirect:/login";
        } else {
            // email이 존재하고, 비밀번호가 일치할 때
            System.out.println("비밀번호 일치"); //test
            httpSession.setAttribute("user",user);
            return "redirect:/main";
        }
    }

    @GetMapping(value = "/loginSuccess")
    public String loginComplete(@SocialUser User user) {
        User loginUser = userService.findByEmail(user.getEmail()).get();
        loginUser.setLastVisitDate();
        loginUser.countVisitNum();
        loginUser.setStatusNormal();
        userService.saveUser(loginUser);
        return "redirect:/main";
    }

    @PostMapping("/create")
    public String create(User user){
        // 비밀번호 암호화
        String rawPassword = user.getPassword();
        user.setEncodePassword(rawPassword);

        user.setCreatedDate();
        user.setLastVisitDate();
        user.setStatusNormal();

        userService.saveUser(user);

        return "redirect:/login";
    }

    @RequestMapping("/changeStatus")
    public String changeStatus(@RequestBody @RequestParam("email") String email){
        User selectedUser = userService.findByEmail(email).get();
        if(selectedUser.getStatus().equals("normal")){
            selectedUser.setStatusBlocked();
        }else {
            selectedUser.setStatusNormal();
        }
        userService.saveUser(selectedUser);
        return "redirect:/admin/usersData";
    }

}