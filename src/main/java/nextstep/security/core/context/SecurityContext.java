package nextstep.security.core.context;

import nextstep.security.core.Authentication;

public interface SecurityContext {

    Authentication getAuthentication();

    void setAuthentication(Authentication authentication);
}

