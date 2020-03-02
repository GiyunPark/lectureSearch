package com.lecturesearch.lecture.contents;

import org.springframework.data.elasticsearch.repository.ElasticsearchRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CartRepository extends ElasticsearchRepository<CartVO, String> {
    //장바구니 리스트
    Iterable<CartVO> findAllByEmail(String email);

    //장바구니 담기
    CartVO save(CartVO paramVO);

    //장바구니 삭제
    void deleteById(String cartIdx);

    //장바구니 모든회원 리스트
    Iterable<CartVO> findAll();
}
