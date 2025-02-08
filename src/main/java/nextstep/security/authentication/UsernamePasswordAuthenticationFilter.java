package nextstep.security.authentication;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import nextstep.security.core.Authentication;
import nextstep.security.core.context.SecurityContext;
import nextstep.security.core.context.SecurityContextHolder;
import nextstep.security.exception.AuthenticationServiceException;
import org.springframework.web.filter.GenericFilterBean;

public class UsernamePasswordAuthenticationFilter extends GenericFilterBean {
    private static final String DEFAULT_REQUEST_URI = "/login";

    private final AuthenticationManager authenticationManager;

    public UsernamePasswordAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
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

            if (authenticate == null) {
                chain.doFilter(request, response);
                return;
            }

            SecurityContext context = SecurityContextHolder.getContext();
            context.setAuthentication(authenticate);
            SecurityContextHolder.setContext(context);

        } catch (AuthenticationServiceException e) {
            ((HttpServletResponse) response).setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        } catch (Exception e) {
            ((HttpServletResponse) response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }

    }
}
