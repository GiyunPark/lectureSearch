package com.lecturesearch.lecture;

import com.lecturesearch.lecture.user.User;
import com.lecturesearch.lecture.user.repository.UserRepository;
import com.lecturesearch.lecture.user.resolver.UserArgumentResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.time.LocalDateTime;
import java.util.List;

@SpringBootApplication
public class LectureApplication implements WebMvcConfigurer {

    public static void main(String[] args) {

        SpringApplication.run(LectureApplication.class, args);
    }

    @Autowired
    private UserArgumentResolver userArgumentResolver;

    @Override
    public void addArgumentResolvers(
            List<HandlerMethodArgumentResolver> argumentResolvers
    ) {
        argumentResolvers.add(userArgumentResolver);
    }

    @Bean
    public CommandLineRunner runner(
            UserRepository userRepository
    ) throws Exception {
        return (args) -> {
            User user = userRepository.save(User.builder()
                    .name("devandy")
                    .password("1234")
                    .email("dev.youngjinmo@gmail.com")
                    .createdDate(LocalDateTime.now())
                    .build());
        };
    }

}
