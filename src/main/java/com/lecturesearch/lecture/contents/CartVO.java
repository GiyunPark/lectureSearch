package com.lecturesearch.lecture.contents;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.elasticsearch.annotations.Document;

@Document(indexName = "cart", type = "contents")
@Data
public class CartVO {

    @Id
    private String cartIdx;
    private String contentsIdx;
    private String email;


    public String getEmail() {
        return email;
    }

    public String getContentsIdx() {
        return contentsIdx;
    }
}
