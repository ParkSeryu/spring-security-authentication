package nextstep.security.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.Principal;
import nextstep.security.core.Authentication;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class UsernamePasswordAuthenticationTokenTest {
    Object principal = new Object();
    Object credentials = new Object();

    @DisplayName("getName - principal의 name 반환")
    @Test
    void getNameReturnsPrincipalName() {
        // given
        Principal sut = () -> "princiaplName";

        // when
        Authentication authentication = new UsernamePasswordAuthenticationToken(sut, credentials, false);

        // then
        assertThat(authentication.getName()).isEqualTo(sut.getName());
    }

    @DisplayName("getName - 속하지 않을 시 빈문자열 반환")
    @Test
    void getNameReturnsBlankString() {
        // given
        String sut = "parkSeryu";

        // when
        Authentication authentication = new UsernamePasswordAuthenticationToken(sut, credentials, false);

        // then
        assertThat(authentication.getName()).isEqualTo("");
    }


}