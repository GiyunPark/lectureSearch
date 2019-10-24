package com.lecturesearch.lecture.user.config;

import com.lecturesearch.lecture.user.SocialType;
import com.lecturesearch.lecture.user.oauth.ClientResources;
import com.lecturesearch.lecture.user.oauth.UserTokenService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.filter.CharacterEncodingFilter;
import org.springframework.web.filter.CompositeFilter;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.List;

import static com.lecturesearch.lecture.user.SocialType.FACEBOOK;
import static com.lecturesearch.lecture.user.SocialType.GOOGLE;
import static com.lecturesearch.lecture.user.SocialType.KAKAO;


@Configuration
@EnableWebSecurity
@EnableOAuth2Client
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    // WebSecurityConfigurerAdapter = security 최적화설정

    @Autowired
    private OAuth2ClientContext oAuth2ClientContext;

    @Override
    protected void configure(HttpSecurity https) throws Exception {
        CharacterEncodingFilter filter = new CharacterEncodingFilter();
        https
            .authorizeRequests()
                .antMatchers("/", "/login/**", "/css/**", "/images/**", "/js/**", "/console/**").permitAll()
                .anyRequest().authenticated()
            .and()
                .headers().frameOptions().disable()
            .and()
                .exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
            .and()
                .formLogin()
                .successForwardUrl("/board/list")
            .and()
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/")
                .deleteCookies("JSESSIONID")
                .invalidateHttpSession(true)
            .and()
                .addFilterBefore(filter, CsrfFilter.class)
                .addFilterBefore(oauth2Filter(), BasicAuthenticationFilter.class)
                .csrf().disable();
    }

    @Bean
    public FilterRegistrationBean oauth2ClientFilterRegistration(
            OAuth2ClientContextFilter filter
    ) {

        // OAuth2 클라이언트용 시큐리티 필터 OAuth2ClientContextFilter를 불러와서
        // 스프링 시큐리티 필터가 실행되기 전 낮은 순서로 동작하도록 설정하는 메서드

        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(filter);
        registration.setOrder(-100);
        return registration;
    }

    private Filter oauth2Filter(){
        CompositeFilter filter = new CompositeFilter();
        List<Filter> filters = new ArrayList<>();
        filters.add(oauth2Filter(facebook(), "/login/facebook", FACEBOOK));
        filters.add(oauth2Filter(google(), "/login/google", GOOGLE));
        filters.add(oauth2Filter(kakao(), "/login/kakao", KAKAO));
        filter.setFilters(filters);
        return filter;
    }

    private Filter oauth2Filter(
            ClientResources client,
            String path,
            SocialType socialType
    ) {
        OAuth2ClientAuthenticationProcessingFilter filter =
                new OAuth2ClientAuthenticationProcessingFilter(path);

        OAuth2RestTemplate template = new OAuth2RestTemplate(
                client.getClient(), // 인증이 수행될 경로를 넣어 OAuth2 클라이언트용 인증 처리 필터 생성
                oAuth2ClientContext // 서버와의 통신을 위한 OAuth2RestTemplate 생성
        );

        filter.setRestTemplate(template);

        // User의 권한을 최적화해서 생성하기 위해
        // UserInfoTokenService를 상속받는 UserTokenService를 생성.
        // 생성한 UserTokenService를 필터의 서비스로 등록
        filter.setTokenServices(new UserTokenService(client, socialType));

        // 인증이 성공되었을 경우(로그인 성공)
        // 리다이렉트될 URL 설정
        filter.setAuthenticationSuccessHandler(
                (request, response, authentication) -> response.sendRedirect(
                        "/"+socialType.getValue()+"/complete"
                )
        );

        // 인증 실패시(로그인 실패)
        // 리다이렉트될 URL을 설정
        filter.setAuthenticationFailureHandler(
                (request, response, exception) -> response.sendRedirect("/error")
        );

        return filter;
    }


    @Bean
    @ConfigurationProperties("facebook")
    public ClientResources facebook(){
        return new ClientResources();
    }

    @Bean
    @ConfigurationProperties("google")
    public ClientResources google(){
        return new ClientResources();
    }

    @Bean
    @ConfigurationProperties("kakao")
    public ClientResources kakao(){
        return new ClientResources();
    }
}
