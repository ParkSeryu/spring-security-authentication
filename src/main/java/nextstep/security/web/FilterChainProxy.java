package nextstep.security.web;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;
import org.springframework.web.filter.GenericFilterBean;

public class FilterChainProxy extends GenericFilterBean {

    private List<SecurityFilterChain> filterChains;

    public FilterChainProxy(List<SecurityFilterChain> filterChains) {
        this.filterChains = filterChains;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        List<Filter> filters = getFilters((HttpServletRequest) request);

        VirtualFilterChain virtualFilterChain = new VirtualFilterChain(filters, chain);
        virtualFilterChain.doFilter(request, response);
    }

    private List<Filter> getFilters(HttpServletRequest request) {
        for (SecurityFilterChain filterChain : filterChains) {
            if (filterChain.matches(request)) {
                return filterChain.getFilters();
            }
        }
        return null;
    }

    public static final class VirtualFilterChain implements FilterChain {
        private final FilterChain originalChain;
        private final List<Filter> additionalFilters;
        private int currentPosition = 0;

        public VirtualFilterChain(List<Filter> additionalFilters, FilterChain chain) {
            this.additionalFilters = additionalFilters;
            this.originalChain = chain;
        }

        @Override
        public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
            if (currentPosition == additionalFilters.size()) {
                originalChain.doFilter(request, response);
            } else {
                Filter nextFilter = additionalFilters.get(currentPosition++);
                nextFilter.doFilter(request, response, this);
            }
        }
    }
}
