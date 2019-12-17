package com.lecturesearch.lecture;

import org.apache.http.HttpHost;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.transport.client.PreBuiltTransportClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
import org.springframework.data.elasticsearch.core.ElasticsearchTemplate;
import org.springframework.data.elasticsearch.repository.config.EnableElasticsearchRepositories;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

@Configuration
@EnableElasticsearchRepositories(basePackages = "com.lecturesearch.lecture.*")
public class EsConfig {

//로컬 ElasticSearch server 이용시

//    @Bean
//    Client client() throws UnknownHostException {
//        Settings settings = Settings.builder()
//                .put("cluster.name", "122473194981:lecture")
//                .build();
//        TransportClient client = new PreBuiltTransportClient(settings);
//        client.addTransportAddress(new TransportAddress(InetAddress.getByName("127.0.0.1")
//                , 9300));
//        return client;
//    }

    //AWS ElasticSearch sever 이용시
    @Bean
    public RestHighLevelClient client() {
        return new RestHighLevelClient(RestClient.builder(HttpHost.create("https://search-lecture-bhdskc4zi274juz5ltfaxsjexy.ap-northeast-2.es.amazonaws.com")));
    }


//    public ElasticsearchOperations elasticsearchTemplate() throws Exception {
//        return new ElasticsearchTemplate(client());
//    }

    //Embedded Elasticsearch Server
    /*@Bean
    public ElasticsearchOperations elasticsearchTemplate() {
        return new ElasticsearchTemplate(nodeBuilder().local(true).node().client());
    }*/

    //테스트

    //        InetAddress address[]= Inet4Address.getAllByName("search-lecture-bhdskc4zi274juz5ltfaxsjexy.ap-northeast-2.es.amazonaws.com");
//        for(InetAddress each : address){
//            System.out.println("Name: " + each.getHostName());
//            System.out.println("Addr: " + each.getHostAddress());
//            System.out.println("Canonical: " + each.getCanonicalHostName());
//        }

}