package com.lecturesearch.lecture;

import com.lecturesearch.lecture.OAuth2.annotation.SocialUser;
import com.lecturesearch.lecture.OAuth2.domain.User;
import com.lecturesearch.lecture.contents.ContentsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletResponse;

@Controller
@RequestMapping("/")
public class HomeController {

    @Autowired
    private ContentsService contentsService;

//    @RequestMapping("/")
//    public String main(Model model, @ModelAttribute ContentsVO paramVO) {
//        Iterable<ContentsVO> rsList = contentsService.contentsList();
//        model.addAttribute("list", rsList);
//        return "/layout/main";
//    }

    @RequestMapping(value = "/main")
    public String list(@PageableDefault Pageable pageable, Model model, HttpServletResponse response, @SocialUser User user) {
        Page i = contentsService.findContentsList(pageable);
        model.addAttribute("pageList", i);

        // 로그인시 사용자이름 화면에서 출력
        if(user != null){
            model.addAttribute("user", user);
        }
        response.setContentType("multipart/form-data");
        return "layout/main";
    }
}
