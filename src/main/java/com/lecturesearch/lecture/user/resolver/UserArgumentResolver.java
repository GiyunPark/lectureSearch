package com.lecturesearch.lecture.user.resolver;

import com.lecturesearch.lecture.user.SocialType;
import com.lecturesearch.lecture.user.annotation.SocialUser;
import com.lecturesearch.lecture.user.User;
import com.lecturesearch.lecture.user.repository.UserRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.MethodParameter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import javax.servlet.http.HttpSession;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import static com.lecturesearch.lecture.user.SocialType.FACEBOOK;
import static com.lecturesearch.lecture.user.SocialType.GOOGLE;
import static com.lecturesearch.lecture.user.SocialType.KAKAO;

@Component
public class UserArgumentResolver implements HandlerMethodArgumentResolver {

    private UserRepository userRepository;

    public UserArgumentResolver(UserRepository userRepository){
        this.userRepository = userRepository;
    }

    // MethodParameter로 해당 파라미터의 정보를 받으며인,
    // 파라미터에서 @SocialUser 어노테이션이 있고 타입이 User인 파라미터인 true를 반환
    @Override
    public boolean supportsParameter(MethodParameter parameter){
        return parameter.getParameterAnnotation(SocialUser.class) != null && parameter.getParameterType().equals(User.class);
    }

    public Object resolveArgument(
            MethodParameter parameter,
            ModelAndViewContainer mavContainer,
            NativeWebRequest webRequest,
            WebDataBinderFactory binderFactory
            ) throws Exception {

        HttpSession session = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest().getSession();

        User user = (User) session.getAttribute("user");

        return getUser(user, session);
    }

    // 인증된 User 객체를 만드는 메인 메서드
    private Object getUser(User user, HttpSession session) {
        if (user==null){
            try{
                OAuth2Authentication authentication = (OAuth2Authentication)
                        SecurityContextHolder.getContext().getAuthentication();

                Map<String, String> map = (HashMap<String, String>) authentication.getUserAuthentication().getDetails();

                User convertUser = convertUser(String.valueOf(authentication.getAuthorities().toArray()[0]), map);

                user = userRepository.findByEmail(convertUser.getEmail());

                if (user==null) {
                    user = userRepository.save(convertUser);
                }

                setRoleIfNotSame(user, authentication, map);
                session.setAttribute("user", user);
            } catch (ClassCastException e){
                return user;
            }
        }
        return user;
    }

    // 사용자의 인증된 소셜 미디어 타입에 따라 빌더를 사용하여 User 객체를 만들어주는 가교 역할
    private User convertUser(String authority, Map<String, String> map) {
        if(FACEBOOK.isEquals(authority)) {
            return getModernUser(FACEBOOK, map);
        } else if(GOOGLE.isEquals(authority)) {
            return getModernUser(GOOGLE, map);
        } else if(KAKAO.isEquals(authority)) {
            return getModernUser(KAKAO, map);
        }
        return null;
    }

    // FACEBOOK/GOOGLE처럼 명명규칙이 공통적인 그룹을 User 객체로 매핑해주는 메서드
    private User getModernUser(SocialType socialType, Map<String, String>map){
        return User.builder()
                .name(map.get("name"))
                .email(map.get("email"))
                .principal(map.get("principal"))
                .socialType(socialType)
                .createdDate(LocalDateTime.now())
                .build();
    }

    // 카카오의 key의 네이밍이 FACEBOOK/GOOGLE과 달라서 생성한 카카오 로그인 전용 메서드
    private User getKakaoUser(Map<String, String> map){
        HashMap<String, String> propertyMap = (HashMap<String, String>)(Object)map.get("properties");
        return User.builder()
                .name(propertyMap.get("username"))
                .email(map.get("kakao_email"))
                .principal(String.valueOf(map.get("id")))
                .socialType(KAKAO)
                .createdDate(LocalDateTime.now())
                .build();
    }

    private void setRoleIfNotSame(
            User user,
            OAuth2Authentication authentication,
            Map<String, String> map
    ) {
        if(!authentication.getAuthorities().contains(
                new SimpleGrantedAuthority(user.getSocialType().getRoleType()))) {
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(
                            map, "N/A",
                            AuthorityUtils.createAuthorityList(
                                    user.getSocialType().getRoleType())));
        }
    }

}
