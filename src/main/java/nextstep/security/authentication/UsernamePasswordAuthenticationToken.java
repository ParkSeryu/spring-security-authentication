package nextstep.security.authentication;

import java.security.Principal;
import nextstep.security.UserDetails;
import nextstep.security.core.Authentication;

public class UsernamePasswordAuthenticationToken implements Authentication {
    private final Object principal;
    private final Object credentials;
    private final boolean authenticated;

    public UsernamePasswordAuthenticationToken(Object principal, Object credentials, boolean authenticated) {
        this.principal = principal;
        this.credentials = credentials;
        this.authenticated = authenticated;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public boolean isAuthenticated() {
        return this.authenticated;
    }

    @Override
    public String getName() {
        Object name = this.getPrincipal();
        if (name instanceof UserDetails userDetails) {
            return userDetails.getUsername();
        }
        if (name instanceof Principal principal) {
            return principal.getName();
        }
        return "";
    }
}
