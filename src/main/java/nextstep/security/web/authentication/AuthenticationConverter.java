package nextstep.security.web.authentication;

import jakarta.servlet.http.HttpServletRequest;
import nextstep.security.core.Authentication;

public interface AuthenticationConverter {

    Authentication convert(HttpServletRequest request);
    
}
