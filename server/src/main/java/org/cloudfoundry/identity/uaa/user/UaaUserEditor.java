
package org.cloudfoundry.identity.uaa.user;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.core.authority.AuthorityUtils;

import java.beans.PropertyEditorSupport;
import java.util.Arrays;
import java.util.List;

public class UaaUserEditor extends PropertyEditorSupport {

    private static String SHORT_FORMAT = "unm|pwd{|comma-separated-authorities}";
    private static String LONG_FORMAT = "unm|pwd|email|fname|lname{|comma-separated-authorities}";
    private static List<String> SUPPORTED_FORMATS = Arrays.asList(SHORT_FORMAT, LONG_FORMAT);

    @Override
    public void setAsText(String text) throws IllegalArgumentException {
        String[] values = text.split("\\|", -1);
        String username = values[0];
        String password = null, email = username, firstName = null, lastName = null, origin = OriginKeys.UAA;
        String authorities = null;

        if (values.length >= 2) {
            switch (values.length) {
                case 2:
                    password = values[1];
                    break;
                case 3:
                    password = values[1];
                    authorities = values[2];
                    break;
                case 5:
                    password = values[1];
                    email = values[2];
                    firstName = values[3];
                    lastName = values[4];
                    break;
                case 6:
                    password = values[1];
                    email = values[2];
                    firstName = values[3];
                    lastName = values[4];
                    authorities = values[5];
                    break;
                case 7:
                    password = values[1];
                    email = values[2];
                    firstName = values[3];
                    lastName = values[4];
                    authorities = values[5];
                    origin = values[6];
                    break;
                default:
                    throw new IllegalArgumentException("Supported formats: " + SUPPORTED_FORMATS);
            }
        }

        UaaUser user = new UaaUser(username, password, email, firstName, lastName, origin, IdentityZoneHolder.get().getId());
        if (authorities != null) {
            user = user.authorities(AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
        }
        super.setValue(user);
    }

}
