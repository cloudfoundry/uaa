

package org.cloudfoundry.identity.uaa.oauth;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * Authentication token representing a user decoded from a UAA access token.
 * 
 * @author Dave Syer
 * 
 */
public class RemoteUserAuthentication extends AbstractAuthenticationToken implements Authentication {

    private String id;
    private String username;
    private String email;

    public RemoteUserAuthentication(String id, String username, String email,
                    Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.id = id;
        this.username = username;
        this.email = email;
        this.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return "<N/A>";
    }

    @Override
    public Object getPrincipal() {
        return username;
    }

    public String getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

}
