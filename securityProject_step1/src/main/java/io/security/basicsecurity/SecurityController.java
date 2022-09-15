package io.security.basicsecurity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index(){
        return "home";
    }

    @GetMapping("/loginPage")
    public String loginPage(){
        return "loginPage";
    }

    @GetMapping("/user")
    public String user(){
        return "user";
    }

    @GetMapping("/admin/pay")
    public String adminPay(){
        return "adminPay";
    }

    @GetMapping("/admin/**")
    public String admin(){
        return "admin";
    }

    @GetMapping("denied")
    public String denied(){
        return "Access is denide";
    }

    @GetMapping("/login")
    public String login(){
        return "login";
    }


    @GetMapping("/SecurityContextHolder")
    public String securityContextHolder(HttpSession session){

        //인증한 사용자 정보를 Security에서 바로 가져옴
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        //session에도 SecurityContext와 동일한 정보가 저장됨
        SecurityContext context = (SecurityContext)session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication1 = context.getAuthentication();

        return "home";
    }

    @GetMapping("/thread")
    public String thread(){

        //SecurityContextHolder 모드에 따른 스레드 별 Context 공유 테스트
        new Thread(
                new Runnable() {
                    @Override
                    public void run() {
                        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();


                        /*아래 조건은 보통 Config에 설정함*/
                        //자식 스레드는 부모의 SecurityContext 정보를 공유 받음
//                        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);

                        //스레드 간 SecurityContext를 공유 하지 않음
//                        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_THREADLOCAL);

                        //SecurityContext 정보를 글로벌로 선언함.
//                        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_GLOBAL);
                    }
                }
        ).start();

        return "thread";
    }
}
