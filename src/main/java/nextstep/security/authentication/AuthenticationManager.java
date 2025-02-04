package nextstep.security.authentication;

import nextstep.security.core.Authentication;

public interface AuthenticationManager {
    Authentication authenticate(Authentication authentication);
}
