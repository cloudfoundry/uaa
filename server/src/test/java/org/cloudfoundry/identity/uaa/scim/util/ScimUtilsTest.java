package org.cloudfoundry.identity.uaa.scim.util;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(PollutionPreventionExtension.class)
class ScimUtilsTest {

    @Test
    void userWithEmptyandNonEmptyEmails() {
        ScimUser user = new ScimUser(null, "josephine", "Jo", "Jung");
        List<ScimUser.Email> emails = new ArrayList<>();
        ScimUser.Email email1 = new ScimUser.Email();
        email1.setValue("sample@sample.com");
        emails.add(email1);
        ScimUser.Email email2 = new ScimUser.Email();
        email2.setValue("");
        emails.add(email2);
        user.setEmails(emails);

        assertThrows(InvalidScimResourceException.class, () -> ScimUtils.validate(user));
    }

    @Test
    void userWithEmptyEmail() {
        ScimUser user = new ScimUser(null, "josephine", "Jo", "Jung");
        List<ScimUser.Email> emails = new ArrayList<>();
        ScimUser.Email email = new ScimUser.Email();
        email.setValue("");
        emails.add(email);
        user.setEmails(emails);

        assertThrows(InvalidScimResourceException.class, () -> ScimUtils.validate(user));
    }

    @Test
    void userWithNonAsciiUsername() {
        ScimUser user = new ScimUser(null, "joe$eph", "Jo", "User");
        user.setOrigin(OriginKeys.UAA);
        user.addEmail("jo@blah.com");

        assertThrows(InvalidScimResourceException.class, () -> ScimUtils.validate(user));
    }

}
