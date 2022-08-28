package com.cos.security1.config;


import com.cos.security1.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;


//secured 어노테이션 활성화 : securedEnabled
//preAuthorized 어노테이션 활성화 :prePostEnabled
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@EnableWebSecurity // 스프링 시큐리티 필터(SecurityConfig)가 스프링 필터체인에 등록된다
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    //@Bean을 적으면 해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다
    @Bean
    public BCryptPasswordEncoder encoderPwd(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //csrf 회원가입 post할 때 자꾸 403에러 발생
        //참고 사이트 : https://swk3169.tistory.com/entry/Web-CSRFCross-Site-Request-Forgery-%EA%B3%B5%EA%B2%A9-%EA%B8%B0%EB%B2%95
        http.csrf().disable();
        http.authorizeRequests()
                //해당 엔드포인트를 들어가려면 인증이 필요하다 : 로그인 한사람만 들어올 수 있음
                .antMatchers("/user/**").authenticated() // 인증만 되면 들어갈 수 있는 주소
                //access권한 : 로그인했지만, admin이나 manager권한이 있어야 입장가능
                .antMatchers("/manager/**")
                .access("hasRole('ROLE_ADMIN')or hasRole('ROLE_MANAGER')")
                //로그인했지만 admin권한만 들어갈 수 잇따
                .antMatchers("/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                //위에 3개가 아닌 이상 모든 권한이 해당됨
                .anyRequest().permitAll()
                //권한이 없을 경우, user,manager,admin페이지로 갈때 forbidden으로 막히지 않게
                //loginPage함수로 login페이지로 이동 시킴(view 있을때 활용)
                .and()
                .formLogin()
                .loginPage("/loginForm")
                // loginProcessingUrl함수로 /login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행해줍니다.
                // controller /login을 만들어주지 않아도 됨
                .loginProcessingUrl("/login")

                //PrincipalDetailsService파일 내 loadUserByUsername의 파라미터를 변경하고 싶을 경우
                //아래처럼 만들어라 -> 근데 바꾸지말고 username쓰는게 편하겠죠?
                //.usernameParameter("username2")

                // 로그인이 성공시 이동되는 url
                // .loginPage("/loginForm")해당 페이지에서 로그인을 하면 /로 보내줄건데,
                //특정페이지를 요청해서 로그인하게 되면 그 페이지를 열어줄게!!! => 넘나 좋음
                //예를 들어 user페이지로 검색후 loginForm에서 로그인시 유저페이지로 이동
                //근데 admin페이지는 403에러
                .defaultSuccessUrl("/")
                .and()
                //.formLogin()이 되어있기 때문에 인증이 필요하면 무조건 .loginPage("/loginForm")로 가게 되어있음
                .oauth2Login()
                .loginPage("/loginForm")//구글로그인이 완료된 뒤 인증까지 됬지만 후처리가 필요함(세션등록)
                // 1. 코드받기(인증됨-로그인됨-정상적인 사용자라는 의미)
                // 2. 엑새스 토큰받기(구글로 로그인한 사용자의 정보에 접근할 수 있는 권한이 생김)
                // 3. 사용자프로필 정보 가져오기
                // 4-1. 그 정보를 토대로 회원가입을 자동으로 진행시키기도 함
                // 4-2. 추가적인 정보가 필요할 경우 회원가입 자동으로 진행 X
                // (구글에 있던 정보는 이메일,전화번호,이름,아이디 뿐) 쇼핑몰 -> (집주소) , 백화점몰 -> (vip등급, 일반등급)
                .userInfoEndpoint()
                .userService(principalOauth2UserService);// 구글로그인 완료 후처리 Tip. 코드 X, (엑세스토큰 + 사용자프로필정보 O )
    }
}
