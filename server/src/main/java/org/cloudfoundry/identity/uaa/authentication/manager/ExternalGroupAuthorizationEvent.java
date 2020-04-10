

package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class ExternalGroupAuthorizationEvent extends AuthEvent {

    public Collection<? extends GrantedAuthority> getExternalAuthorities() {
        return externalAuthorities;
    }

    private Collection<? extends GrantedAuthority> externalAuthorities;

    private boolean addGroups = false;

    public ExternalGroupAuthorizationEvent(UaaUser user, boolean userModified, Collection<? extends GrantedAuthority> externalAuthorities, boolean addGroups) {
        super(user, userModified);
        this.addGroups = addGroups;
        this.externalAuthorities = externalAuthorities;
    }

    public boolean isAddGroups() {
        return addGroups;
    }
}
