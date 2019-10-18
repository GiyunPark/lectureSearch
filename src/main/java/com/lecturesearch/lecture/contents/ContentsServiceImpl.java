package com.lecturesearch.lecture.contents;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
public class ContentsServiceImpl implements ContentsService {

    @Autowired
    private ContentsRepository contentsRepository;

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

    @Override
    public Page<ContentsVO> findContentsList(Pageable pageable) {
        pageable = PageRequest.of(pageable.getPageNumber() <= 0 ? 0 : pageable.getPageNumber() - 1, pageable.getPageSize());
        return contentsRepository.findAll(pageable);
    }

//    @Override
//    public ContentsVO detailView(int no) {
//        return contentsRepository.findById(no).orElse(new ContentsVO());
//    }

    //아래는 Test용 메서드

}
