package nextstep.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nextstep.security.exception.AuthenticationException;
import nextstep.security.util.Base64Convertor;
import org.springframework.http.HttpHeaders;
import org.springframework.web.filter.OncePerRequestFilter;

public class BasicAuthenticationFilter extends OncePerRequestFilter {
    private final UserDetailsService userDetailsService;
    public static final String AUTHENTICATION_SCHEME_BASIC = "Basic";

    public BasicAuthenticationFilter(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
        try {
            checkAuthentication(request);
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    private void checkAuthentication(HttpServletRequest request) {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authorization == null || !authorization.startsWith(AUTHENTICATION_SCHEME_BASIC)) {
            throw new AuthenticationException();
        }

        String credentials = authorization.split(" ")[1];
        String decodedString = Base64Convertor.decode(credentials);
        String[] usernameAndPassword = decodedString.split(":");
        String username = usernameAndPassword[0];
        String password = usernameAndPassword[1];

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if (!userDetails.getPassword().equals(password)) {
            throw new AuthenticationException();
        }
    }
}
