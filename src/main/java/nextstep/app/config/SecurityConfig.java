package nextstep.app.config;

import java.util.List;
import nextstep.app.domain.Member;
import nextstep.app.domain.MemberRepository;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.authentication.AuthenticationProvider;
import nextstep.security.authentication.BasicAuthenticationFilter;
import nextstep.security.authentication.DaoAuthenticationProvider;
import nextstep.security.authentication.ProviderManager;
import nextstep.security.authentication.UsernamePasswordAuthenticationFilter;
import nextstep.security.core.userdetails.UserDetails;
import nextstep.security.core.userdetails.UserDetailsService;
import nextstep.security.web.DefaultSecurityFilterChain;
import nextstep.security.web.FilterChainProxy;
import nextstep.security.web.SecurityFilterChain;
import nextstep.security.web.context.HttpSessionSecurityContextRepository;
import nextstep.security.web.context.SecurityContextHolderFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.DelegatingFilterProxy;

@Configuration
public class SecurityConfig {
    private final MemberRepository memberRepository;

    public SecurityConfig(MemberRepository memberRepository) {
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
    public DelegatingFilterProxy delegatingFilterProxy() {
        return new DelegatingFilterProxy(filterChainProxy(List.of(securityFilterChain())));
    }

    @Bean
    public FilterChainProxy filterChainProxy(List<SecurityFilterChain> securityFilterChains) {
        return new FilterChainProxy(securityFilterChains);
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        AuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider(userDetailsService());
        return new ProviderManager(List.of(daoAuthenticationProvider));
    }

    @Bean
    public SecurityFilterChain securityFilterChain() {
        return new DefaultSecurityFilterChain(
                List.of(
                        new SecurityContextHolderFilter(new HttpSessionSecurityContextRepository()),
                        new UsernamePasswordAuthenticationFilter(authenticationManager()),
                        new BasicAuthenticationFilter(authenticationManager())
                )
        );
    }
}