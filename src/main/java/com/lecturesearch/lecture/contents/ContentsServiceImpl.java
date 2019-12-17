package com.lecturesearch.lecture.contents;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class ContentsServiceImpl implements ContentsService {

    @Autowired
    private ContentsRepository contentsRepository;

    @Autowired
    private ReviewRepository reviewRepository;

    @Autowired
    private CartRepository cartRepository;

    //콘텐츠 리스트 보기
//    @Override
//    public Iterable<ContentsVO> contentsList() {
//        return contentsRepository.findAll();
//    }

    //콘텐츠 등록
    @Override
    public ContentsVO insert(ContentsVO paramVO) {
        return contentsRepository.save(paramVO);
    }

    //페이징 리스트보기
    @Override
    public Page<ContentsVO> findContentsList(Pageable pageable) {
        pageable = PageRequest.of(pageable.getPageNumber() <= 0 ? 0 : pageable.getPageNumber() - 1, pageable.getPageSize());
        return contentsRepository.findAll(pageable);
    }

    //콘텐츠 상세보기
    @Override
    public ContentsVO detailView(String idx) {
        return contentsRepository.findById(idx).orElse(new ContentsVO());
    }

    //서치후 페이징리스트보기
    @Override
    public Page<ContentsVO> searchTitle(String title, Pageable pageable) {
        pageable = PageRequest.of(pageable.getPageNumber() <= 0 ? 0 : pageable.getPageNumber() - 1, pageable.getPageSize());
        return contentsRepository.findAllByTitle(title, pageable);
    }

    @Override
    public ReviewVO reviewWrite(ReviewVO paramVO) {
        return reviewRepository.save(paramVO);
    }

    @Override
    public ContentsVO contentSave(ContentsVO contentsVO) {
        return contentsRepository.save(contentsVO);
    }

    @Override
    public void deleteContent(String idx) {
        contentsRepository.deleteById(idx);
    }

    @Override
    public CartVO cartInsert(CartVO paramVO) {
        return cartRepository.save(paramVO);
    }

    @Override
    public void cartDelete(String contentsIdx) {
        cartRepository.deleteById(contentsIdx);
    }

    @Override
    public Page<ReviewVO> findReviewList(String contentsIdx, Pageable pageable) {
        pageable = PageRequest.of(pageable.getPageNumber() <= 0 ? 0 : pageable.getPageNumber() - 1, pageable.getPageSize());
        return reviewRepository.findAllByContentsIdx(contentsIdx, pageable);
    }

    @Override
    public void reviewDelete(String idx) {
        reviewRepository.deleteById(idx);
    }

    @Override
    public Iterable<CartVO> cartList(String email) {
        return cartRepository.findAllByEmail(email);
    }

    public Optional<ContentsVO> findById(String idx) {
        return contentsRepository.findById(idx);
    }

//    public Page<CartVO> cartList(String email, Pageable pageable) {
//        pageable = PageRequest.of(pageable.getPageNumber() <= 0 ? 0 : pageable.getPageNumber() - 1, pageable.getPageSize());
//        return cartRepository.findAllByEmail(email, pageable);
//    }

    @Override
    public List<ContentsVO> findAll(){
        return contentsRepository.findAll();
    }

    @Override
    public List<String> saveImages(MultipartFile[] files) {
        String imageName = null;
        List<String> imagesList = new ArrayList<>();
        for (int i = 0; i < files.length; i++) {
            try {
                imageName = HashEncryption.sha256(files[i].getOriginalFilename() + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
                imagesList.add(imageName);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
//            File targetFile = new File("/Users/home/Java/git_clone/lectureSearch/src/main/resources/static/userImages/"+ imageName+".jpg");
            File targetFile = new File("/home/ec2-user/app/image/" + imageName + ".jpg");
            try {
                files[i].transferTo(targetFile);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return imagesList;
    }
}

