package nextstep.security.web.context;

import static org.assertj.core.api.Assertions.assertThat;

import nextstep.security.authentication.UsernamePasswordAuthenticationToken;
import nextstep.security.core.Authentication;
import nextstep.security.core.context.SecurityContext;
import nextstep.security.core.context.SecurityContextImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

class HttpSessionSecurityContextRepositoryTest {
    private static final String SPRING_SECURITY_CONTEXT_KEY = "SPRING_SECURITY_CONTEXT";

    MockHttpSession session = new MockHttpSession();
    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();
    Authentication authenticationToken = new UsernamePasswordAuthenticationToken(
            "parkSeryu", "password", false);
    SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
    SecurityContext securityContext = new SecurityContextImpl(authenticationToken);

    @BeforeEach
    void setUp() {
        request.setSession(session);
    }

    @AfterEach
    void tearDown() {
        session.clearAttributes();
    }

    @DisplayName("HttpSessionSecurityContextRepository - 세션에 있는 인증 정보를 불러 온다.")
    @Test
    void loadContext_LoadSecurityContextFromHttpSession() {
        // given
        Authentication authentication = createAuthentication("parkSeryu", "password", false);
        SecurityContext securityContext = createSecurityContext(authentication);
        session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, securityContext);

        // when
        SecurityContext sut = securityContextRepository.loadContext(request);

        // then
        assertThat(sut.getAuthentication().getPrincipal()).isEqualTo("parkSeryu");
        assertThat(sut.getAuthentication().getCredentials()).isEqualTo("password");
    }

    @DisplayName("HttpSessionSecurityContextRepository - 세션이 없는 경우 새로운 Security Context 생성 한다.")
    @Test
    void createContext_LoadSecurityContextFromHttpSession() {
        // given
        session.clearAttributes();

        // when
        SecurityContext sut = securityContextRepository.loadContext(request);

        // then
        assertThat(sut).isNotNull();
        assertThat(sut.getAuthentication()).isNull();
    }


    @DisplayName("HttpSessionSecurityContextRepository - 세션에 인증 정보를 저장 한다.")
    @Test
    void saveContext_SaveSecurityContextToHttpSession() {
        // given
        Authentication authentication = createAuthentication("parkSeryu", "password", false);
        SecurityContext securityContext = createSecurityContext(authentication);

        // when
        securityContextRepository.saveContext(securityContext, request, response);

        // then
        SecurityContext savedContext = (SecurityContext) session.getAttribute(SPRING_SECURITY_CONTEXT_KEY);
        assertThat(savedContext.getAuthentication().getPrincipal()).isEqualTo("parkSeryu");
        assertThat(savedContext.getAuthentication().getCredentials()).isEqualTo("password");
    }

    private Authentication createAuthentication(String username, String password, boolean authenticated) {
        return new UsernamePasswordAuthenticationToken(username, password, authenticated);
    }

    private SecurityContext createSecurityContext(Authentication authentication) {
        return new SecurityContextImpl(authentication);
    }

}