package com.lecturesearch.lecture.OAuth2.domain;

import com.lecturesearch.lecture.OAuth2.SocialType;
import com.lecturesearch.lecture.OAuth2.password.PasswordEncoding;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.elasticsearch.annotations.Document;

import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

@Data
@NoArgsConstructor
@Document(indexName = "user", type = "info")
public class User {

    @Id
    private String idx;
    private String name;
    private String email;
    private String password;
    private String principal;
    @Enumerated(EnumType.STRING)
    private SocialType socialType;
    private String createdDate;
    private String lastVisitDate;
    private String status;
    private long numOfVisit;


    @Builder
    public User(String name, String password,
                String email, String createdDate, String lastVisitDate,
                String principal, SocialType socialType, String status, long numOfVisit){
        this.name=name;
        this.password=password;
        this.email=email;
        this.principal=principal;
        this.socialType=socialType;
        this.createdDate=createdDate;
        this.lastVisitDate=lastVisitDate;
        this.status=status;
        this.numOfVisit=numOfVisit;
    }

    public void setEncodePassword(String password){
        PasswordEncoding passwordEncoding = new PasswordEncoding();
        this.password = passwordEncoding.encode(password);
    }

    public String getPassword() {
        return this.password;
    }

    public void setCreatedDate(){//facebook, google 에서 제공하는 시간대와 맞춤
        this.createdDate=LocalDateTime.ofInstant(new Date().toInstant(), ZoneId.systemDefault()).toString();
    }
    public void setLastVisitDate() {
        this.lastVisitDate=LocalDateTime.ofInstant(new Date().toInstant(), ZoneId.systemDefault()).toString();
    }
    public void setStatusNormal(){
        this.status="normal";
    }
    public void setStatusBlocked(){
        this.status="blocked";
    }
    public void countVisitNum(){
        this.numOfVisit+=1;
    }

}
