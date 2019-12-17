package com.lecturesearch.lecture.OAuth2.service;

import com.lecturesearch.lecture.OAuth2.domain.User;

import java.util.List;
import java.util.Optional;

public interface UserService {

    void saveUser(User user);

    List<User> findAll();

    Optional<User> findByEmail(String email);

    void deleteUser(String idx);
}
