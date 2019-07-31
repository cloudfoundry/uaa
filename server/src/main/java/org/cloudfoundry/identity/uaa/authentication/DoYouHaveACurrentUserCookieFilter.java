package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.login.CurrentUserInformation;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLDecoder;
import java.util.Collections;

public class DoYouHaveACurrentUserCookieFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(DoYouHaveACurrentUserCookieFilter.class);

    private final UaaUserDatabase userDatabase;

    public DoYouHaveACurrentUserCookieFilter(UaaUserDatabase userDatabase) {
        this.userDatabase = userDatabase;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            Cookie[] cookies = request.getCookies();
            if (cookies == null) {
                cookies = new Cookie[]{};
            }
            logger.info(String.format("this many cookies %d", cookies.length));

            for (int i = 0; i < cookies.length; i++) {
                Cookie cookie = cookies[i];
                if ("Current-User".equals(cookie.getName())) {
                    logger.info("Found Current-User cookie");

                    String userId = JsonUtils.readValue(URLDecoder.decode(cookie.getValue()), CurrentUserInformation.class).getUserId();

                    logger.info(String.format("Looking for user %s", userId));
                    UaaUser user = userDatabase.retrieveUserById(userId);
                    SecurityContextHolder.setContext(new SecurityContextImpl(new UaaAuthentication(
                            new UaaPrincipal(user),
                            Collections.emptyList(),
                            new UaaAuthenticationDetails(request)
                    )));
                    logger.info("set the security context");
                }
            }
        } catch (UsernameNotFoundException e) {
            logger.error("BTW, something weird happened in this filter?", e);
            // WILL WE REGRET THIS?
        }
        filterChain.doFilter(request, response);
    }
}
