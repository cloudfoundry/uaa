
package org.cloudfoundry.identity.uaa.user;

import java.util.Map;
import java.util.Objects;

import org.springframework.security.core.GrantedAuthority;

@SuppressWarnings("serial")
public class ExtendedUaaAuthority implements GrantedAuthority {

    private String authority;

    private Map<String, String> additionalInfo;

    public ExtendedUaaAuthority(String authority, Map<String, String> additionalInfo) {
        this.authority = authority;
        this.additionalInfo = additionalInfo;
    }

    @Override
    public String getAuthority() {
        return authority;
    }

    public Map<String, String> getAdditionalInfo() {
        return additionalInfo;
    }

    @Override
    public String toString() {
        return authority;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null)
            return false;
        if (obj == this)
            return true;
        if (!(obj instanceof ExtendedUaaAuthority))
            return false;

        ExtendedUaaAuthority e = (ExtendedUaaAuthority) obj;
        if (Objects.equals(e.getAuthority(), authority) && e.additionalInfo.equals(additionalInfo)) {
            return true;
        }
        else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }

}
