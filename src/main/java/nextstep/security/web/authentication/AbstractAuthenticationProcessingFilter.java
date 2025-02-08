package nextstep.security.web.authentication;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.core.Authentication;
import nextstep.security.core.context.SecurityContext;
import nextstep.security.core.context.SecurityContextHolder;
import nextstep.security.exception.AuthenticationException;
import nextstep.security.exception.AuthenticationServiceException;
import nextstep.security.web.context.HttpSessionSecurityContextRepository;
import nextstep.security.web.context.SecurityContextRepository;
import org.springframework.web.filter.GenericFilterBean;

public abstract class AbstractAuthenticationProcessingFilter extends GenericFilterBean {

    private String requestUri; // RequestMatcher 대용
    private AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    public AbstractAuthenticationProcessingFilter(String defaultRequestUri,
                                                  AuthenticationManager authenticationManager) {
        setRequestUri(defaultRequestUri);
        setAuthenticationManager(authenticationManager);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;

        if (!this.requestUri.equals(httpServletRequest.getRequestURI())) {
            chain.doFilter(request, response);
            return;
        }

        try {
            Authentication authenticationResult = attemptAuthentication(httpServletRequest, httpServletResponse);

            if (authenticationResult == null) {
                chain.doFilter(request, response);
                return;
            }
            successfulAuthentication(httpServletRequest, httpServletResponse, authenticationResult);

        } catch (AuthenticationServiceException e) {
            ((HttpServletResponse) response).setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            unsuccessfulAuthentication();
        } catch (Exception e) {
            ((HttpServletResponse) response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            unsuccessfulAuthentication();
        }
    }

    private void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                          Authentication authenticationResult) {
        SecurityContext context = SecurityContextHolder.getContext();
        context.setAuthentication(authenticationResult);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, request, response);
    }

    private void unsuccessfulAuthentication() {
        SecurityContextHolder.clearContext();
    }

    public abstract Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException;

    protected AuthenticationManager getAuthenticationManager() {
        return this.authenticationManager;
    }

    private void setRequestUri(String requestUri) {
        this.requestUri = requestUri;
    }

    private void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }
}
