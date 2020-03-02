package com.lecturesearch.lecture.contents;

import com.lecturesearch.lecture.OAuth2.domain.User;
import com.lecturesearch.lecture.OAuth2.annotation.SocialUser;
import com.lecturesearch.lecture.OAuth2.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

@Controller
@RequestMapping("/contents")
public class ContentsController {

    @Autowired
    private ContentsService contentsService;

    @Autowired
    private UserRepository userRepository;

    @RequestMapping("/detail")

    public String detailView(String idx, Model model, @PageableDefault Pageable pageable,
                             @SocialUser User socialUser,Principal principal, HttpServletResponse response) {
        User user =null;
        if(!(socialUser==null&&principal==null)) {
            if (socialUser == null) {
                user = userRepository.findByEmail(principal.getName()).get();
            } else {
                user = socialUser;
            }
        }
        ContentsVO contents = contentsService.detailView(idx);
        Page page = contentsService.findReviewList(idx, pageable);
        model.addAttribute("contents", contents);
        model.addAttribute("review", page);
        model.addAttribute("user", user);

        response.setContentType("multipart-form/data");
        return "contents/detailView";
    }

    @RequestMapping("/boardform")
    public String boardForm(@SocialUser User socialUser, Principal principal, Model model) {
        User user;
        if(socialUser==null) {
            user = userRepository.findByEmail(principal.getName()).get();
        }else{
            user = socialUser;
        }
        model.addAttribute("user", user);
        return "layout/boardForm";
    }

    @RequestMapping("/updateContent")
    public String updateContent(@SocialUser User socialUser,Principal principal, Model model, String idx) {
        User user;
        if(socialUser==null) {
            user = userRepository.findByEmail(principal.getName()).get();
        }else{
            user = socialUser;
        }
        ContentsVO i = contentsService.detailView(idx);
        model.addAttribute("user", user);
        model.addAttribute("content",i);
        return "layout/boardForm";
    }
    @RequestMapping("deleteContent")
    public String deleteContent(String idx){
         contentsService.deleteContent(idx);
         //강의삭제시 장바구니도 삭제
        Iterable<CartVO> cartAllList = contentsService.cartList();
        ArrayList<String> arrayList = new ArrayList<>();
        for(CartVO allList : cartAllList){
            if(allList.getContentsIdx().contains(idx)){
                arrayList.add(allList.getCartIdx());
                for(int i = 0; i < arrayList.size(); i++){
                    contentsService.cartDelete(arrayList.get(i));
                }
            }
        }
         return "redirect:/main";
    }

    //후기작성
    @RequestMapping("/review")
    public String reviewWrite(@ModelAttribute ReviewVO paramVO, String contentsIdx) {
        contentsService.reviewWrite(paramVO);
        contentsService.averageStar(Integer.parseInt(paramVO.getStar()), contentsIdx);
        return "redirect:/contents/detail?idx="+contentsIdx;
    }

    //후기삭제
    @RequestMapping("/reviewDelete")
    public String reviewDelete(String idx, String contentsIdx, Pageable pageable){
        ReviewVO reviewVO = contentsService.reviewVO(idx);
        contentsService.reviewDelete(idx);
        contentsService.averageStarDelete(Integer.parseInt(reviewVO.getStar()), contentsIdx);
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

        ContentsVO contentsVO= contentsService.findById(contentIdx).get();
        contentsVO.setTitle(title);
        contentsVO.setAuthor(author);
        contentsVO.setPrice(price);
        contentsVO.setRunningTime(runningTime);
        contentsVO.setCreatedDate(createdDate);
        contentsVO.setDescription(description);

        if(!files[0].isEmpty()){
            imagesList=contentsService.saveImages(files);
            contentsVO.setImages(imagesList);
        }

        contentsService.contentSave(contentsVO);
        response.setContentType("multipart/form-data");
        return "redirect:/main";
    }

    @RequestMapping("/cartList")
    public String cartList(@PageableDefault Pageable pageable, @SocialUser User socialUser,Principal principal, Model model) {
        User user;
        if(socialUser==null) {
            user = userRepository.findByEmail(principal.getName()).get();
        }else{
            user = socialUser;
        }
        String email = user.getEmail();
        Iterable<CartVO> cartList = contentsService.cartList(email);

        ArrayList<String> arrListContentsIdx = new ArrayList<String>();
        ArrayList<String> arrListCartIdx = new ArrayList<String>();
        for(CartVO cart : cartList){
            arrListContentsIdx.add(cart.getContentsIdx());
            arrListCartIdx.add(cart.getCartIdx());
        }
        List<ContentsVO> cartContentsList = new ArrayList<>();
        for (String k : arrListContentsIdx) {
            cartContentsList.add(contentsService.detailView(k));
        }
        model.addAttribute("user", user);
        model.addAttribute("cartContentsList", cartContentsList);
        model.addAttribute("cartIdxList", arrListCartIdx);
        return "contents/cartList";
    }

    @RequestMapping(value = "/loadImage", method = RequestMethod.GET)
    public void loadImage(String image, HttpServletResponse response) throws IOException {
//        File file = new File("/home/ec2-user/app/step1/lectureSearch/src/main/resources/static/userImages/",image+".jpg");
        //로컬 테스트
        File file = new File("/Users/home/Java/git_clone/lectureSearch/src/main/resources/static/userImages/",image+".jpg");
        FileInputStream fileInputStream = new FileInputStream(file);
        response.setContentLength((int)file.length());
        response.setCharacterEncoding("utf-8");

        OutputStream outputStream = response.getOutputStream();

        FileCopyUtils.copy(fileInputStream, outputStream);

        outputStream.flush();
        fileInputStream.close();
        outputStream.close();
    }

    @RequestMapping("/cartInsert")
    public String cartInsert(@ModelAttribute CartVO paramVO, @SocialUser User socialUser, @RequestParam String contentsIdx, Principal principal){
        String email;
        User user = null;
        if(socialUser != null){
            email = socialUser.getEmail();
        } else {
            user = userRepository.findByEmail(principal.getName()).get();
            email = user.getEmail();
        }

        //email값에 해당하는 카트리스트를 뽑아온다
        Iterable<CartVO> i = contentsService.cartList(email);
        ArrayList<String> arrListContentsIdx = new ArrayList<String>();
        String cartIdx = "";
        //카트리스트에 들어있는 컨텐츠의 index값을 arrayList에 저장한다
        for(CartVO cart : i) {
            arrListContentsIdx.add(cart.getContentsIdx());
        }
        boolean verify = true;
        String contentsIndex = contentsIdx;
        //카트리스트에 이미 저장되있는지 검사
        for (String s : arrListContentsIdx) {
            if (s.equals(contentsIndex)) {
                verify = false;
                int cartIndexOf = s.indexOf(contentsIndex);
                ArrayList<String> arrListCartIdx = new ArrayList<String>();
                for (CartVO cart : i) {
                    arrListCartIdx.add(cart.getCartIdx());
                }
                cartIdx = arrListCartIdx.get(cartIndexOf);
            }
        }

        if(verify){
            contentsService.cartInsert(paramVO);
        } else {
            contentsService.cartDelete(cartIdx);
        }
        return "redirect:/contents/cartList";
    }

    @RequestMapping("/cartDelete")
    public String cartDelete(String cartIdx){
            contentsService.cartDelete(cartIdx);
        return "redirect:/contents/cartList";
    }
}