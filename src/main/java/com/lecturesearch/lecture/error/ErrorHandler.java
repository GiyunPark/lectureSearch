package com.lecturesearch.lecture.error;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ErrorHandler {
    @GetMapping("/error")
    public void errorpage(){
        // public String errorpage()
        // throw new IllegalStateException("Error");
    }
}