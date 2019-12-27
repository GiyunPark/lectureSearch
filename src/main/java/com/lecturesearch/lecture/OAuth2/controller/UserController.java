package com.lecturesearch.lecture.OAuth2.controller;

import com.lecturesearch.lecture.OAuth2.domain.User;
import com.lecturesearch.lecture.OAuth2.annotation.SocialUser;
import com.lecturesearch.lecture.OAuth2.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import java.security.Principal;


@Controller
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping("/login")
    public String login(){
        return "form";
    }

    @ResponseBody
    @RequestMapping(value="/emailChk.do", method=RequestMethod.POST)
    public int emailCheck(@RequestBody String email) {
        int result = 0;
        if(userService.findByEmail(email).isPresent()){
            // return value != null
            result = 0; // value!=null 이면 0 반환
        } else {
            result = 1; // value==null 이면 1 반환
        }
        return result;
    }

    // OAuth2를 통한 로그인 요청
    @GetMapping(value = "/loginSuccess")
    public String loginComplete(@SocialUser User user) {
        User loginUser = userService.findByEmail(user.getEmail()).get();
        loginUser.setLastVisitDate();
        loginUser.countVisitNum();
        loginUser.setStatusNormal();
        userService.saveUser(loginUser);
        return "redirect:/main";
    }

    @GetMapping(value = "/loginSuccessByFormLogin")
    public String FormLoginComplete(Principal principal){
        User loginUser = userService.findByEmail(principal.getName()).get();
        loginUser.setLastVisitDate();
        loginUser.countVisitNum();
        loginUser.setStatusNormal();
        userService.saveUser(loginUser);
        return "redirect:/main";
    }

    @PostMapping("/create")
    public String create(User user){
        user.setEncodePassword(user.getPassword());  // 비밀번호 암호화

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