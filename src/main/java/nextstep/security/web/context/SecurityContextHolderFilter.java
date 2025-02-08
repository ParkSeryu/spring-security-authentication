package nextstep.security.web.context;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import nextstep.security.core.context.SecurityContext;
import nextstep.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

public class SecurityContextHolderFilter extends GenericFilterBean {
    private final SecurityContextRepository securityContextRepository;

    public SecurityContextHolderFilter(SecurityContextRepository securityContextRepository) {
        this.securityContextRepository = securityContextRepository;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        try {
            HttpServletRequest httpServletRequest = (HttpServletRequest) request;

            SecurityContext securityContext = securityContextRepository.loadContext(httpServletRequest);
            SecurityContextHolder.setContext(securityContext);

            chain.doFilter(request, response);

        } finally {
            SecurityContextHolder.clearContext();
        }

    }
}
