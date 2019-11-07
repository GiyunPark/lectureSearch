package com.lecturesearch.lecture.contents;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.elasticsearch.annotations.Document;

@Document(indexName = "lecture", type = "contents")
@Data
public class ContentsVO {

    @Id
    private String idx;
    private String title;
    private String author;
    private String subject;
    private String images;
    private int price;
    private String description;
    private String createdDate;
    private String runningTime;
    private String registrationDate;

    public ContentsVO() {}

//    public ContentsVO(String no, String title, String subject, String price, String uploadDate, String runningTime) {
//        this.no = no;
//        this.title = title;
//        this.subject = subject;
//        this.price = price;
//        this.uploadDate = uploadDate;
//        this.runningTime = runningTime;
//    }

    public ContentsVO(String title, String author, String subject, String images, int price, String description, String createdDate, String runningTime, String registrationDate) {
        this.title = title;
        this.author = author;
        this.subject = subject;
        this.images = images;
        this.price = price;
        this.description = description;
        this.createdDate = createdDate;
        this.runningTime = runningTime;
        this.registrationDate = registrationDate;
    }
}
