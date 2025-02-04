package nextstep.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.authentication.DaoAuthenticationProvider;
import nextstep.security.authentication.ProviderManager;
import nextstep.security.authentication.UsernamePasswordAuthenticationToken;
import nextstep.security.core.Authentication;
import nextstep.security.exception.AuthenticationServiceException;
import org.springframework.web.filter.GenericFilterBean;

public class UsernamePasswordAuthenticationFilter extends GenericFilterBean {
    private static final String SPRING_SECURITY_CONTEXT_KEY = "SPRING_SECURITY_CONTEXT";
    private static final String DEFAULT_REQUEST_URI = "/login";

    private final AuthenticationManager authenticationManager;

    public UsernamePasswordAuthenticationFilter(UserDetailsService userDetailsService) {
        this.authenticationManager = new ProviderManager(List.of(new DaoAuthenticationProvider(userDetailsService)));
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (!DEFAULT_REQUEST_URI.equals(((HttpServletRequest) request).getRequestURI())) {
            chain.doFilter(request, response);
            return;
        }
        
        try {
            HttpServletRequest httpServletRequest = (HttpServletRequest) request;

            if (!"POST".equalsIgnoreCase(httpServletRequest.getMethod())) {
                throw new AuthenticationServiceException();
            }

            Map<String, String[]> parameterMap = request.getParameterMap();
            String username = parameterMap.get("username")[0];
            String password = parameterMap.get("password")[0];

            Authentication authenticate = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password, false));

            HttpSession session = ((HttpServletRequest) request).getSession();
            session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, authenticate);

        } catch (AuthenticationServiceException e) {
            ((HttpServletResponse) response).setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        } catch (Exception e) {
            ((HttpServletResponse) response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }

    }
}
