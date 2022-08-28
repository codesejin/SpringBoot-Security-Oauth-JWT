package com.cos.security1.auth;

//시큐리티가 /login주소 요청이 오면 낚아채서 로그인을 진행시킨다.
// 로그인이 진행 완료되면 시큐리티 session을 만들어줍니다. (Security ContextHolder)
// 일반적인 session 과 시큐리티 session이 다르다
// 세션공간은 똑같은데 시큐리티가 자신만의 세션공간을 가짐 -> Security ContextHolder 여기에 세션 정보를 저장함
//시큐리티가 가지고 있는 세션에 들어갈 수 있는 object가 정해져있음
//오브젝트 타입 => Authentication타입 객체
//Authentication안에 User정보가 있어야 됨
// User오브젝트 타입 => UserDetails 타입 객체

import com.cos.security1.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

// 시큐리티 세션에 세션정보를 저장해주는데, 여기에 들어갈 수 있는 객체가 Authentication 객체여야합
// Authentication안에 들어갈 수 있는 유저정보는 UserDetails타입이어야한다
// Security Session <- Authentication <- UserDetails(PrincipalDetails)

public class PrincipalDetails implements UserDetails {

    private User user; // 콤포지션

    public PrincipalDetails(User user) {
        this.user = user;
    }

    //해당 User의 권한을 리턴하는 곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        //권한이라면 role을 리턴하면 되는데, role의 타입이 String이라 반환이 안됨
        //user.getRole(); -> 반환타입 맞춰서 Collection으로 해줘야함
        //ArrayList는 Collection의 자식이다
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    //패스워드를 리턴
    @Override
    public String getPassword() {
        return user.getPassword();
    }

    //유저네임 리턴
    @Override
    public String getUsername() {
        return user.getUsername();
    }

    //네 계정 만료되었니?
    @Override
    public boolean isAccountNonExpired() {
        return true;//아니오
    }

    //네 계정 잠겼니?
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    //네 계정의 비밀번호가 만료기한을 지났니? 오래사용한거 아니니?
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    //네 계정이 활성화되었니?
    @Override
    public boolean isEnabled() {
        //false로 할 경우의 예시
        //우리 사이트!! 1년동안 회원이 로그인을 안하면!! 휴면 계정하기로 함
        //User객체에  private  Timestamp loginDate; 필드를 추가하고
        //user.getLogindate();
        // 현재시간 - 로그인시간 => 1년을 초과하면 return false;
        return true;
    }
}
