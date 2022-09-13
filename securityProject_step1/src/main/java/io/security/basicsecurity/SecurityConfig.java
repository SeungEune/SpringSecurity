package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//
////      인가 초기화
//        http
//                .authorizeRequests()
//                .anyRequest().authenticated();
////      인증 초기화
//        http
//                .formLogin()
////                .loginPage("/loginPage")/*내가 직접 꾸민 Html 파일로 설정 할 수 있다. url을 보내는 것임...*/
//                .defaultSuccessUrl("/")
//                .failureUrl("/login")
//                .usernameParameter("userId")
//                .passwordParameter("passwd")
//                .loginProcessingUrl("/login_proc")
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        System.out.println("authentiocation : " + authentication.getName());
//                        response.sendRedirect("/");
//                    }
//                })
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                        System.out.println("exception : " + exception.getMessage());
//                        response.sendRedirect("/login");
//                    }
//                })
//                .permitAll()/*인증 받지 않아도 이동할 수 있는 페이지(login 페이지는 인증이 없어도 이동이 가능해야한다.)*/;



        /*로그아웃 처리 관련*/
        http
                .authorizeRequests()
                .anyRequest().authenticated();

        http
                .formLogin();

        http
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")/*logoutSuccessHandler와 다른 점은 이건 단순 Url 이동만 담당함.*/
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                });

        /*remember-me 기능 관련*/
        http
                .rememberMe()
                .rememberMeParameter("remember") //remember-me 체크박스 테그 name을 같게 해줘야한다.
                .tokenValiditySeconds(3600)
                .alwaysRemember(false) //remember-me 기능 체크박스가 활성화 되지 않아도 항상 실행 여부
                .userDetailsService(userDetailsService) //스프링부트 3.7.3에서는 userDetailesService가 바뀜...?
//                .rememberMeCookieName("cookie rename")/*쿠키 명 변경 메소드*/
        ;
    }
}
