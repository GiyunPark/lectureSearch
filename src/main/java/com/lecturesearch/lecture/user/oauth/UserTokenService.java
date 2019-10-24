package com.lecturesearch.lecture.user.oauth;

import com.lecturesearch.lecture.user.SocialType;
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.List;
import java.util.Map;

public class UserTokenService extends UserInfoTokenServices {
    // 소셜미디어 원격 서버와 통신하는 로직을 갖고있는 UserInfoTokenServices를 상속받아
    // 통신에 필요한 값만 넣어주어 설정
    public UserTokenService(
            ClientResources resources,
            SocialType socialType
    ) {
        super(resources.getResource().getUserInfoUri(),
                resources.getClient().getClientId());

        setAuthoritiesExtractor(new OAuth2AuthoritiesExtractor(socialType));
    }

    public static class OAuth2AuthoritiesExtractor implements AuthoritiesExtractor {
        private String socialType;

        public OAuth2AuthoritiesExtractor(SocialType socialType){
            this.socialType = socialType.getRoleType();
        }

        @Override
        public List<GrantedAuthority> extractAuthorities(Map<String, Object> map) {
            return AuthorityUtils.createAuthorityList(this.socialType);
        }
    }
}
