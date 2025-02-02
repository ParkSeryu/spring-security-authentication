package nextstep.app;

import nextstep.app.domain.Member;
import nextstep.app.domain.MemberRepository;
import nextstep.security.BasicAuthenticationFilter;
import nextstep.security.UserDetails;
import nextstep.security.UserDetailsService;
import nextstep.security.UsernamePasswordAuthenticationFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    private final MemberRepository memberRepository;

    public WebConfig(MemberRepository memberRepository) {
        this.memberRepository = memberRepository;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            Member member = memberRepository.findByEmail(username)
                    .orElseThrow(() -> new IllegalArgumentException("해당하는 사용자를 찾을 수 없습니다."));
            return new UserDetails() {
                @Override
                public String getUsername() {
                    return member.getEmail();
                }

                @Override
                public String getPassword() {
                    return member.getPassword();
                }
            };
        };
    }

    @Bean
    public FilterRegistrationBean<OncePerRequestFilter> basicAuthFilter() {
        FilterRegistrationBean<OncePerRequestFilter> filterRegistrationBean = new FilterRegistrationBean<>();

        filterRegistrationBean.setFilter(new BasicAuthenticationFilter(userDetailsService()));

        filterRegistrationBean.addUrlPatterns("/members");

        return filterRegistrationBean;
    }

    @Bean
    public FilterRegistrationBean<GenericFilterBean> usernamePasswordAuthenticationFilter() {
        FilterRegistrationBean<GenericFilterBean> filterRegistrationBean = new FilterRegistrationBean<>();

        filterRegistrationBean.setFilter(new UsernamePasswordAuthenticationFilter(userDetailsService()));

        filterRegistrationBean.addUrlPatterns("/login");

        return filterRegistrationBean;
    }
}
