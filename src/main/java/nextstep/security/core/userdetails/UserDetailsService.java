package nextstep.security.core.userdetails;

public interface UserDetailsService {
    UserDetails loadUserByUsername(String username);
}
