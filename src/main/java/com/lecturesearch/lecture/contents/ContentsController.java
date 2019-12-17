package com.lecturesearch.lecture.contents;

import com.lecturesearch.lecture.OAuth2.domain.User;
import com.lecturesearch.lecture.OAuth2.annotation.SocialUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.List;

@Controller
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

    @RequestMapping("/detail")
    public String detailView(String idx, Model model, @PageableDefault Pageable pageable,
                             @SocialUser User user, HttpServletResponse response) {
        ContentsVO contents = contentsService.detailView(idx);
        Page page = contentsService.findReviewList(idx, pageable);
        model.addAttribute("contents", contents);
        model.addAttribute("review", page);
        model.addAttribute("user", user);

        response.setContentType("multipart-form/data");
        return "contents/detailView";
    }

//    @RequestMapping("/insert")
//    public String write() {
//        //임시 데이터저장용
//        for(int i = 0; i < 30; i++){
//            ContentsVO paramVO = new ContentsVO("양념가득 치킨"+i, "인프런","파이썬","img_4.jpg",55000,"파이썬은 문법 구조가 쉽기 때문에 프로그래밍을 처음 접하는 초보자도 쉽게 이해할 수 있어요. 파이썬은 그 어떤 프로그래밍 언어보다 확장성이 월등히 높은 언어에요. 데이터분석가도, 웹개발자도, 머신러닝 연구자도, 대학원생도 파이썬을 사용하죠. 당신이 어떤 업무를 맡더라도 파이썬만 알아두면 척척 대응하기 쉬워집니다.\n" +
//                    "\n" +
//                    "당연히 비전공자도 다룰 수 있습니다. 프로그래밍 언어는 만국공통어에요. 만약 C, Java 등의 언어를 접해봤다면 더욱 쉽게 파이썬을 익힐 수 있겠죠.\n" +
//                    "\n" +
//                    "파이썬의 기본부터 심화까지 차근차근 따라해보세요. 인프런이 제시하는 프로그래밍 학습 로드맵을 따라가면 어느덧 파이썬 프로그래밍을 마스터한 자신과 만나게 될 겁니다. ","2019년 7월 16일","12시간 39분", LocalDateTime.now().toString());
//            contentsService.insert(paramVO);
//        }
//     return "redirect:/main";
//    }


    @RequestMapping("/boardform")
    public String boardForm(@SocialUser User user, Model model) {
        model.addAttribute("user", user);
        return "layout/boardForm";
    }

    @RequestMapping("/updateContent")
    public String updateContent(@SocialUser User user, Model model, String idx) {
        ContentsVO i = contentsService.detailView(idx);
        model.addAttribute("user", user);
        model.addAttribute("content",i);
        return "layout/boardForm";
    }
    @RequestMapping("deleteContent")
    public String deleteContent(String idx){
         contentsService.deleteContent(idx);
         return "redirect:/main";
    }

    //후기작성
    @RequestMapping("/review")
    public String reviewWrite(@ModelAttribute ReviewVO paramVO, String contentsIdx) {
        contentsService.reviewWrite(paramVO);
        return "redirect:/contents/detail?idx="+contentsIdx;
    }

    //후기삭제
    @RequestMapping("/reviewDelete")
    public String reviewDelete(String idx, String contentsIdx){
        contentsService.reviewDelete(idx);
        return "redirect:/contents/detail?idx=" +contentsIdx;
    }

//    @PostMapping("/save")
//    @ResponseBody
//    public ResponseEntity<?> saveContent(@RequestBody ContentsVO contentsVO){
//        contentsVO.setRegistrationDate(LocalDateTime.now()
//                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
//        contentsService.contentSave(contentsVO);
//        System.out.println(contentsVO.getImages());
//        System.out.println(contentsVO.getPrice());
//        return new ResponseEntity<>("{}", HttpStatus.CREATED);
//    }

    @RequestMapping(value = "/save", method = RequestMethod.POST,
    consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public String saveContent(@RequestParam("title") String title, @RequestParam("author") String author,
                              @RequestParam("files") MultipartFile[] files, @RequestParam("price") String price,
                              @RequestParam("runningTime") String runningTime, @RequestParam("createdDate") String createdDate,
                              @RequestParam("description") String description, @RequestParam("writer") String writer,
                              HttpServletResponse response){
        List<String> imagesList;

        imagesList = contentsService.saveImages(files);

        ContentsVO contentsVO= ContentsVO.builder()
                .title(title)
                .author(author)
                .images(imagesList)
                .price(price)
                .runningTime(runningTime)
                .createdDate(createdDate)
                .description(description)
                .writer(writer)
                .build();
        contentsVO.setRegistrationDate();
        response.setContentType("multipart-form/data");

        contentsService.contentSave(contentsVO);
        return "redirect:/main";
    }

    @RequestMapping(value = "/update", method = RequestMethod.POST)
    public String updateContent(@RequestParam("title") String title, @RequestParam("author") String author,
                                @RequestParam("files") MultipartFile[] files, @RequestParam("price") String price,
                                @RequestParam("runningTime") String runningTime, @RequestParam("createdDate") String createdDate,
                                @RequestParam("description") String description, @RequestParam("contentIdx") String contentIdx,
                                HttpServletResponse response){
        List<String> imagesList;

        imagesList = contentsService.saveImages(files);

        ContentsVO contentsDTO= ContentsVO.builder()
                .title(title)
                .author(author)
                .images(imagesList)
                .price(price)
                .runningTime(runningTime)
                .createdDate(createdDate)
                .description(description)
                .build();

        ContentsVO contentsVO= contentsService.findById(contentIdx).get();
        contentsVO.update(contentsDTO);

        contentsService.contentSave(contentsVO);
        response.setContentType("multipart/form-data");
        return "redirect:/main";
    }

    @RequestMapping("/cartList")
    public String cartList(@PageableDefault Pageable pageable, @SocialUser User user, Model model) {
        String email = user.getEmail();
        Iterable<CartVO> i = contentsService.cartList(email);

        ArrayList<String> arrList = new ArrayList<String>();
        for(CartVO cart : i){
            arrList.add(cart.getContentsIdx());
        }
        List<ContentsVO> cartList = new ArrayList<>();
        for (String k : arrList) {
            cartList.add(contentsService.detailView(k));
        }
            model.addAttribute("list", cartList);
        return "contents/cartList";
    }

    @RequestMapping("/cartInsert")
    public String cartInsert(@ModelAttribute CartVO paramVO, @SocialUser User user, @RequestParam String contentsIdx){
        String email = user.getEmail();
        Iterable<CartVO> i = contentsService.cartList(email);
        ArrayList<String> arrList = new ArrayList<String>();
        for(CartVO cart : i){
            arrList.add(cart.getContentsIdx());
        }

        boolean verify = true;
        String contentsIndex = paramVO.getContentsIdx();
        for (String s : arrList) {
            if (s.equals(contentsIndex)) {
                verify = false;
            }
        }

        if(verify){
            contentsService.cartInsert(paramVO);
        } else {
            contentsService.cartDelete(contentsIdx);
        }
        return "redirect:/contents/cartList";
    }

    @RequestMapping("/cartDelete")
    public String cartDelete(String contentsIdx){
            contentsService.cartDelete(contentsIdx);
        return "redirect:/contents/cartList";
    }
}
