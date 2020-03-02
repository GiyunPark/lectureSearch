package com.lecturesearch.lecture.search;

import com.lecturesearch.lecture.OAuth2.annotation.SocialUser;
import com.lecturesearch.lecture.OAuth2.domain.User;
import com.lecturesearch.lecture.OAuth2.repository.UserRepository;
import com.lecturesearch.lecture.contents.CartVO;
import com.lecturesearch.lecture.contents.ContentsService;
import com.lecturesearch.lecture.contents.ContentsVO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

@Controller
@RequestMapping("")
public class SearchController {
    private static String saveTitle;

    @Autowired
    ContentsService contentsService;

    @Autowired
    UserRepository userRepository;

    @RequestMapping("/search")
    public String searchContents(@RequestParam String title, @PageableDefault Pageable pageable, Model model, @SocialUser User socialUser, Principal principal) {
        User user = null;
        if(!(socialUser==null&&principal==null)) {
            if (socialUser == null) {
                user = userRepository.findByEmail(principal.getName()).get();
            } else {
                user = socialUser;
            }
        }
        // 장바구니 active
        if(user != null){
            String email = user.getEmail();

            Iterable<CartVO> cartList = contentsService.cartList(email);
            ArrayList<String> arrayList = new ArrayList<String>();
            for(CartVO i : cartList){
                arrayList.add(i.getContentsIdx());
            }
            model.addAttribute("arrList", arrayList);
        }

        //검색결과 출력
        saveTitle = title;
        Page<ContentsVO> resultPage = contentsService.searchTitle(title, pageable);
        model.addAttribute("resultList", resultPage);
        model.addAttribute("user", user);
        return "layout/main";
    }

//    @RequestMapping("/searchResult")
//    public String searchResult(@PageableDefault Pageable pageable, Model model) {
//        Page<ContentsVO> resultPage = contentsService.searchTitle(saveTitle, pageable);
//        model.addAttribute("resultList", resultPage);
//        return "layout/main";
//    }
}
