package nextstep.security.authentication;

import nextstep.security.UserDetails;
import nextstep.security.UserDetailsService;
import nextstep.security.core.Authentication;
import nextstep.security.exception.AuthenticationException;

public class DaoAuthenticationProvider implements AuthenticationProvider {
    private UserDetailsService userDetailsService;

    public DaoAuthenticationProvider(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UserDetails userDetails = userDetailsService.loadUserByUsername(authentication.getPrincipal().toString());
        if (!userDetails.getPassword().equals(authentication.getCredentials())) {
            throw new AuthenticationException();
        }

        return new UsernamePasswordAuthenticationToken(authentication.getPrincipal(),
                authentication.getCredentials(), true);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
