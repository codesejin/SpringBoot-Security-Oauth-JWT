package com.cos.security1.controller;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.xml.ws.Action;

@Controller
public class IndexController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    //localhost:8080/
    //localhost:8080
    @GetMapping({ "", "/" })
    public @ResponseBody String index() {
        return "인덱스 페이지입니다.";
    }


    @GetMapping("/user")
    public @ResponseBody String user(){
        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin(){
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager(){
        return "manager";
    }

    //스프링시큐리티가 해당주소를 낚아채버림 - SecurityConfig파일 생성 후 작동안함
    @GetMapping("/loginForm")
    public String loginForm(){
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user){
        System.out.println(user);
        user.setRole("ROLE_USER");
        String rawPAssword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPAssword);
        user.setPassword(encPassword);
        userRepository.save(user); //회원가입 잘됨. 비밀번호 : 1234 => 시큐리티로 로그인할 수 없음. 이유는 패스워드가 암호화가 안되었기 때문!!
        return "redirect:/loginForm";
    }
    @Secured("ROLE_ADMIN")//특정메서드에 간단하게 권한걸고싶으면 이거 사용
    @GetMapping("/info")
    public @ResponseBody String info(){
        return "개인정보";
    }
    //Secured는 권한 하나만 걸고 싶을때
    //PreAuthorize는 권한 여러개 걸고 싶을때 ( postAuthorize도 있음 )
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")//data메소드가 실행되기 직전에 실행됨
    @GetMapping("/data")
    public @ResponseBody String data(){
        return "데이터정보";
    }
}
