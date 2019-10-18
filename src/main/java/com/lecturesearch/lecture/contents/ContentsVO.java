package com.lecturesearch.lecture.contents;

import lombok.Data;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.elasticsearch.annotations.Document;

@Document(indexName = "dongryeol", type = "contents")
@Data
public class ContentsVO {

    @Id
    private String no;
    private String title;
    private String subject;
    private String price;
    private String uploadDate;
    private String runningTime;
    @CreatedDate
    private String registrationDate;

    public ContentsVO() {}

    public ContentsVO(String no, String title, String subject, String price, String uploadDate, String runningTime) {
        this.no = no;
        this.title = title;
        this.subject = subject;
        this.price = price;
        this.uploadDate = uploadDate;
        this.runningTime = runningTime;
    }

    public ContentsVO(String title, String subject, String price, String uploadDate, String runningTime) {
        this.title = title;
        this.subject = subject;
        this.price = price;
        this.uploadDate = uploadDate;
        this.runningTime = runningTime;
    }
}
