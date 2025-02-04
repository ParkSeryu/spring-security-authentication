package nextstep.security.core;

import java.io.Serializable;
import java.security.Principal;

public interface Authentication extends Principal, Serializable {
    Object getCredentials();

    Object getPrincipal();

    boolean isAuthenticated();

}
