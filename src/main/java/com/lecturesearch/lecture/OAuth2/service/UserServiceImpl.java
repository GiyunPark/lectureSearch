package com.lecturesearch.lecture.OAuth2.service;

import com.lecturesearch.lecture.OAuth2.domain.User;
import com.lecturesearch.lecture.OAuth2.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    UserRepository userRepository;

    @Override
    public void saveUser(User user){
        userRepository.save(user);
    }

    @Override
    public List<User> findAll(){
        return userRepository.findAll();
    }

    @Override
    public Optional<User> findByEmail(String email){
        return userRepository.findByEmail(email);
    }

    @Override
    public void deleteUser(String idx){
        userRepository.deleteById(idx);
    }

}
