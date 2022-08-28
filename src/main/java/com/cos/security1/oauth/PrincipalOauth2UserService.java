package com.cos.security1.oauth;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;


@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
    //여기서 구글 로그인 후 처리 되는 함수
    //구글로 부터 받은 userRequest 데이터에 대한 후처리 되는 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("getClientRegistration = " + userRequest.getClientRegistration());// registrationId로 어떤 Oauth로 로그인했는지 확인

        System.out.println("getAccessToken = " + userRequest.getAccessToken().getTokenValue());
        //구글로그인 버튼 클릭 -> 구글로그인창 -> 로그인완료 -> code를 리턴(Oauth-Client라이브러리) -> AccessToken 요청
        // 위에까지가 UserRequest정보
        //UserRequest정보 -> loadUser함수 호출 -> 구글로부터 회원 프로필받아줌
        System.out.println("getAttributes = " + super.loadUser(userRequest).getAttributes());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        //회원가입을 강제로 진행해볼 예정
        return super.loadUser(userRequest);
    }
}
