package com.lecturesearch.lecture;

import com.lecturesearch.lecture.contents.ContentsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

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

    @RequestMapping("/main")
    public String list(@PageableDefault Pageable pageable, Model model) {
        Page i = contentsService.findContentsList(pageable);
        model.addAttribute("pageList", i);
        return "/layout/main";
    }
}
