package org.cloudfoundry.identity.uaa.web;

import org.cloudfoundry.identity.uaa.UaaConfig;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.web.SecurityFilterChain;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * Represents a Java-managed {@link SecurityFilterChain}. This allows mixing
 * XML-based configuration and Java-based configuration.
 * <p>
 * See {@link UaaConfig#aggregateSpringSecurityFilterChain(WebSecurityConfiguration, List)} for more information.
 *
 * @deprecated Remove this once there are no more XML-based filter chains.
 */
@Deprecated
public class UaaFilterChain implements SecurityFilterChain {

    private final SecurityFilterChain chain;
    private final String name;

    public UaaFilterChain(SecurityFilterChain chain, String name) {
        this.chain = chain;
		this.name = name;
	}

    @Override
    public List<Filter> getFilters() {
        return this.chain.getFilters();
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        return this.chain.matches(request);
    }

    public String getName() {
        return this.name;
    }

    @Override
    public String toString() {
        return this.getClass().getName()+"[" + getName()+", "+getFilters().size()+"]";
    }
}
