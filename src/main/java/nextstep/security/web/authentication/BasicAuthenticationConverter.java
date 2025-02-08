package nextstep.security.web.authentication;

import jakarta.servlet.http.HttpServletRequest;
import nextstep.security.authentication.UsernamePasswordAuthenticationToken;
import nextstep.security.core.Authentication;
import nextstep.security.exception.AuthenticationException;
import nextstep.security.util.Base64Convertor;
import org.springframework.http.HttpHeaders;

public class BasicAuthenticationConverter implements AuthenticationConverter {
    public static final String AUTHENTICATION_SCHEME_BASIC = "Basic";

    @Override
    public Authentication convert(HttpServletRequest request) {

        String header = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (header == null) {
            return null;
        }

        if (!header.startsWith(AUTHENTICATION_SCHEME_BASIC)) {
            throw new AuthenticationException();
        }

        String credentials = header.split(" ")[1];
        String decodedString = Base64Convertor.decode(credentials);
        if (!decodedString.contains(":")) {
            throw new AuthenticationException();
        }
        String[] usernameAndPassword = decodedString.split(":");
        String username = usernameAndPassword[0];
        String password = usernameAndPassword[1];

        return new UsernamePasswordAuthenticationToken(username, password, false);
    }
}
