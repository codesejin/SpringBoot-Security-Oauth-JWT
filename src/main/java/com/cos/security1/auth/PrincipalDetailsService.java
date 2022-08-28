package com.cos.security1.auth;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service//메모리에 욜려줌 // PrincipalDetails는 안띄우는 이유? 나중에 new로 강제로 띄울거임
public class PrincipalDetailsService implements UserDetailsService {
    // Authentication객체를 만들어서 Security Session에 넣어야하는 곳이 여기 파일임
    // 시큐리티 설정에서 .loginProcessingUrl("/login")으로 걸어놨기때문에
    // /login요청이 오면 자동으로 UserDetailsService타입으로 IoC되어있는 loadUserByUsername함수가 실행됨
    // 이거 그냥 규칙이라 외워라

    @Autowired
    private UserRepository userRepository;

    //시큐리티 session(내부 Authentication(내부 userDetails타입))
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("username = " + username);

        //view 로그인단에 username2라고 적혀있으면 파라미터 username안먹힘 -> 이름 동일해야함
        //view단에서 로그인버튼 클릭시 UserDetailsService를 찾아 들어옴
        //loadUserByUsername함수를 발동시켜서 username을 가져옴
        User userEntity = userRepository.findByUsername(username);
        if (userEntity != null){
            //PrincipalDetails안에 꼭 user오브젝트를 넣어줘야 활용하기 편함
            //PrincipalDetails가 리턴될때 Authentication에 쏙 들어감
            //그리고 또 session안에 쏙들어감 => 알아서 loadUserByUsername가 해줌
            return new PrincipalDetails(userEntity);
        }
        return null;
    }
}
