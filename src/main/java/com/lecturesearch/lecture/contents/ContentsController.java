package com.lecturesearch.lecture.contents;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/contents")
public class ContentsController {

    @Autowired
    private ContentsService contentsService;

//    @RequestMapping("/list")
//    public String list(Model model, @ModelAttribute ContentsVO paramVO){
//        Iterable<ContentsVO> rsList = contentsService.contentsList(paramVO);
//        model.addAttribute("list", rsList);
//        return "layout/main";
//    }

//    @RequestMapping("/detail")
//    public String detailView(@RequestParam(value="no", defaultValue = "0") int no, Model model) {
//        ContentsVO i = contentsService.detailView(no);
//        model.addAttribute("contents", i);
//        return "/contents/detailView";
//    }

    @RequestMapping("/insert")
    public String write() {
        //임시 데이터저장용
            ContentsVO paramVO = new ContentsVO("test","자바","만원","7시","30분");
            contentsService.insert(paramVO);
     return "redirect:/list";
    }
}
