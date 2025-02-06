package nextstep.security.web.context;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import nextstep.security.core.context.SecurityContext;
import nextstep.security.core.context.SecurityContextImpl;

public class HttpSessionSecurityContextRepository implements SecurityContextRepository {
    private static final String SPRING_SECURITY_CONTEXT_KEY = "SPRING_SECURITY_CONTEXT";

    @Override
    public SecurityContext loadContext(HttpServletRequest request) {
        HttpSession httpSession = request.getSession(false);
        SecurityContext context = readSecurityContextFromSession(httpSession);

        if (context == null) {
            context = createNewContext();
        }

        return context;
    }

    private SecurityContext createNewContext() {
        return new SecurityContextImpl();
    }

    private SecurityContext readSecurityContextFromSession(HttpSession httpSession) {
        if (httpSession == null) {
            return null;
        }
        Object contextFromSession = httpSession.getAttribute(SPRING_SECURITY_CONTEXT_KEY);

        if (contextFromSession == null) {
            return null;
        }

        if (!(contextFromSession instanceof SecurityContext)) {
            return null;
        }
        return (SecurityContext) contextFromSession;
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession();
        session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, context);
    }
}
