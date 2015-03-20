package org.cloudfoundry.identity.uaa.zone;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.expression.OAuth2ExpressionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * If the X-Identity-Zone-Id header is set and the user has a scope
 * of zones.<id>.admin, this filter switches the IdentityZone in the IdentityZoneHolder
 * to the one in the header.
 * 
 * @author wtran@pivotal.io
 *
 */
public class IdentityZoneSwitchingFilter extends OncePerRequestFilter {

    @Autowired
    public IdentityZoneSwitchingFilter(IdentityZoneProvisioning dao) {
        super();
        this.dao = dao;
    }

    private final IdentityZoneProvisioning dao;
    public static final String HEADER = "X-Identity-Zone-Id";
    
    protected boolean isAuthorizedToSwitchToIdentityZone(String identityZoneId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean hasScope = OAuth2ExpressionUtils.hasAnyScope(authentication,new String[] {"zones."+identityZoneId+".admin"});
        boolean isUaa = IdentityZoneHolder.isUaa();
        boolean isTokenAuth = (authentication instanceof OAuth2Authentication);
        return isTokenAuth && isUaa && hasScope;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        String identityZoneId = request.getHeader(HEADER);
        if (StringUtils.hasText(identityZoneId)) {
            if (!isAuthorizedToSwitchToIdentityZone(identityZoneId)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "User is not authorized to switch to IdentityZone with id "+identityZoneId);
                return;
            }
            IdentityZone originalIdentityZone = IdentityZoneHolder.get();
            try {
                
                IdentityZone identityZone = null;
                try {
                    identityZone = dao.retrieve(identityZoneId);
                } catch (ZoneDoesNotExistsException ex) {
                } catch (EmptyResultDataAccessException ex) {
                } catch (Exception ex) {
                    throw ex;
                }
                if (identityZone == null) {
                    response.sendError(HttpServletResponse.SC_NOT_FOUND, "Identity zone with id "+identityZoneId+" does not exist");
                    return;
                }
                IdentityZoneHolder.set(identityZone);
                filterChain.doFilter(request, response);
            } finally {
                IdentityZoneHolder.set(originalIdentityZone);
            }
        } else {
            filterChain.doFilter(request, response);
        }
    }
}
