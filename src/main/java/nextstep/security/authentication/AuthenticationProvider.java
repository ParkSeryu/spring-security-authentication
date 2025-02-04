package nextstep.security.authentication;

import nextstep.security.core.Authentication;
import nextstep.security.exception.AuthenticationException;

public interface AuthenticationProvider {
    Authentication authenticate(Authentication authentication) throws AuthenticationException;

    boolean supports(Class<?> authentication);
}
