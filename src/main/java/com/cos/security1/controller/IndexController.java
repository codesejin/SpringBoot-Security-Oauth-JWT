package com.cos.security1.controller;

import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;


@Controller
public class IndexController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    //일반사용자 로그인 Authentication 작동 원리
    @GetMapping("/test/login")
    // @AuthenticationPrincipal이라는 어노테이션을 통해 세션정보에 접근할 수 있음
    public @ResponseBody String loginTest(Authentication authentication, @AuthenticationPrincipal PrincipalDetails userDetails){ //DI(의존성주입)
        System.out.println("/test/login ================");
        //30라인 authentication객체 안에 Principal이 있고,
        // Principal의 리턴타입이 object이기 때문에 35번라인 다운캐스팅해서 받아서
        // 38번라인 getUser 호출 ==> 근데 나는 왜 필드가 안나오고 주소값이 나올까?
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

        //Authentication을 dependency injection해서 다운캐스팅 과정 거쳐서 user object를 찾을 수 도 있고,
        System.out.println("authentication = " + principalDetails.getUser());
        // @AuthenticationPrincipal이라는 어노테이션을 통해 getUser을 찾을 수도 있다. 위아래 둘다 같은 데이터
        System.out.println("userDetails = " + userDetails.getUser());
        return "세션정보확인";
    }

    // OAuth2 로그인 Authentication 작동 원리
    @GetMapping("/test/oauth/login")
    public @ResponseBody String loginOAuthTest(Authentication authentication, @AuthenticationPrincipal OAuth2User oauth){ //DI(의존성주입)
        System.out.println("/test/oauth/login ================");
        // ClassCastException해서 오류가 안난다
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("authentication = " + oauth2User.getAttributes());
        //Auth2User.getAttributes()의 정보는 PrincipalOauthUserSerivce파일의 super.loadUser(userRequest).getAttributes()의 정보와 동일
        System.out.println("oAuth2User = " + oauth.getAttributes());
        return "OAuth 세션정보확인";
    }
    // ==========> 로그인 종류별로 인자가 다르기 때문에, 컨트롤러 입장에서 혼란스러움 , 처리하기 복잡
    // 해결방법은 하나의 클래스에 userDetails와 OAuth2User를 implements받고 그 클래스를 부모로 두면
    // authentication객체 자체가 userDetails나 OAuth2User 타입이기만 하면 담을 수 있으므로
    // 그 클래스를 authentication객체에 담아버주면 됨!!! ==> PrincipalDetails

    //localhost:8080/
    //localhost:8080
    @GetMapping({ "", "/" })
    public @ResponseBody String index() {
        return "인덱스 페이지입니다.";
    }


    @GetMapping("/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails){
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
