package nextstep.security.authentication;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import nextstep.security.core.Authentication;
import nextstep.security.core.context.SecurityContextHolder;
import nextstep.security.exception.AuthenticationException;
import nextstep.security.web.authentication.AuthenticationConverter;
import nextstep.security.web.authentication.BasicAuthenticationConverter;
import org.springframework.web.filter.OncePerRequestFilter;

public class BasicAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final AuthenticationConverter authenticationConverter = new BasicAuthenticationConverter();

    public BasicAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {
        try {
            Authentication authRequest = authenticationConverter.convert(request);

            if (authRequest != null) {
                Authentication authResult = authenticationManager.authenticate(authRequest);
                SecurityContextHolder.getContext().setAuthentication(authResult);
            }

            filterChain.doFilter(request, response);
        } catch (AuthenticationException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }
}
