package nextstep.security.authentication;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import nextstep.security.core.Authentication;
import nextstep.security.core.context.SecurityContextHolder;
import nextstep.security.exception.AuthenticationException;
import nextstep.security.util.Base64Convertor;
import org.springframework.http.HttpHeaders;
import org.springframework.web.filter.OncePerRequestFilter;

public class BasicAuthenticationFilter extends OncePerRequestFilter {
    public static final String AUTHENTICATION_SCHEME_BASIC = "Basic";

    private final AuthenticationManager authenticationManager;

    public BasicAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {
        try {
            Authentication authRequest = convert(request);

            if (authRequest != null) {
                Authentication authResult = authenticationManager.authenticate(authRequest);
                SecurityContextHolder.getContext().setAuthentication(authResult);
            }

            filterChain.doFilter(request, response);
        } catch (AuthenticationException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    private Authentication convert(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (header == null) {
            return null;
        }

        if (!header.startsWith(AUTHENTICATION_SCHEME_BASIC)) {
            throw new AuthenticationException();
        }

        String credentials = header.split(" ")[1];
        String decodedString = Base64Convertor.decode(credentials);
        if (!decodedString.contains(":")) {
            throw new AuthenticationException();
        }
        String[] usernameAndPassword = decodedString.split(":");
        String username = usernameAndPassword[0];
        String password = usernameAndPassword[1];

        return authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password, false));
    }

}
