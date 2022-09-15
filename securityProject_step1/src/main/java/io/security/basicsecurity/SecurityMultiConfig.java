package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

//@Configuration
//@EnableWebSecurity
@Order(0) //메서드 실행 순서를 지정 해줌
public class SecurityMultiConfig extends WebSecurityConfigurerAdapter{

    /*다중보안 설정 관련*/

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        /*admin url 접속자 인증*/
        http
                .antMatcher("/admin/**")
                .authorizeRequests()
                .anyRequest().authenticated()
        .and()
                .httpBasic();
    }
}


//@Configuration
@Order(1) //메서드 실행 순서를 지정 해줌
class SecurityConfig2 extends WebSecurityConfigurerAdapter{

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        /*모든 사용자 인증*/
        http
                .authorizeRequests()
                .anyRequest().permitAll()
        .and()
                .formLogin();
    }
}
