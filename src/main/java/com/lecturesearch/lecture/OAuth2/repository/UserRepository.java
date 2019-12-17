package com.lecturesearch.lecture.OAuth2.repository;

import com.lecturesearch.lecture.OAuth2.domain.User;
import org.springframework.data.elasticsearch.repository.ElasticsearchRepository;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends ElasticsearchRepository<User, String> {

    Optional<User> findByEmail(String email);

    List<User> findAll();

}


