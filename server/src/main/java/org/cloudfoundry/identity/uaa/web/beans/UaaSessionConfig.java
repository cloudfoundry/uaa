package org.cloudfoundry.identity.uaa.web.beans;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.jdbc.config.annotation.web.http.EnableJdbcHttpSession;
import org.springframework.session.jdbc.config.annotation.web.http.JdbcHttpSessionConfiguration;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

@Configuration
@EnableJdbcHttpSession
public class UaaSessionConfig {

    @Bean
    public CookieSerializer uaaCookieSerializer(
            final @Value("${servlet.session-cookie.max-age:-1}") int cookieMaxAge
    ) {
        DefaultCookieSerializer cookieSerializer = new DefaultCookieSerializer();
        cookieSerializer.setSameSite(null);
        cookieSerializer.setCookieMaxAge(cookieMaxAge);

        return cookieSerializer;
    }

    @Autowired
    public void customizeIdleTimeout(
            final JdbcHttpSessionConfiguration jdbcHttpSessionConfiguration,
            final @Value("${servlet.idle-timeout:1800}") int idleTimeout) {
        jdbcHttpSessionConfiguration.setMaxInactiveIntervalInSeconds(idleTimeout);
    }
}
