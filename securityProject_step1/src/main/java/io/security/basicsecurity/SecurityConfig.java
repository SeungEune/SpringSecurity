package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
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


        /*동시 세션 제어*/
//        http
//                .sessionManagement()
//                .maximumSessions(1) //최대 허용 가능 세션 수, -1 : 무제한 로그인 세션 허용
//                .maxSessionsPreventsLogin(true) //동시 로그인 차단함, false : 기존 세션 만료(default)
////                .invalidSessionUrl("/invalid") //세션이 유효하지 않을 때 이동 할 페이지
//                .expiredUrl("/expired"); //세션이 만료된 경우 이동 할 페이지


        /*세션 고정 보호*/ //공격자가 내 세션을 이용하여 사용할 수 없도록 로그인시 새로운 세션으로 변경할 것 인지를 설정함.
//        http
//                .sessionManagement()
//                .sessionFixation().changeSessionId(); //기본값(security 버전 3.1 이상에서 사용 가능)
                                                      //none, migrateSession(3.1이하 버전에서 사용), newSession


        /*세션 정책*/
        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
        //SessionCrestionPolicy.Always        : 스프링 시큐리트가 항상 세션 생성
        //SessionCreationPolicy.If_Required   : 스프링 시큐리티가 필요 시 생성(기본값)
        //SessionCreationPoilcy.Never         : 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용
        //SessionCreationPolicy.Stateless     : 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음 -> JWT(Json Web Token)사용할 때 사용
    }
}
