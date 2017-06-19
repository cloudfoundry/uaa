package org.cloudfoundry.identity.uaa.scim.util;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

public class ScimUtilsTest {

    @Test(expected = InvalidScimResourceException.class)
    public void userWithEmptyandNonEmptyEmails() {
        ScimUser user = new ScimUser(null, "josephine", "Jo", "Jung");
        List<ScimUser.Email> emails = new ArrayList<>();
        ScimUser.Email email1 = new ScimUser.Email();
        email1.setValue("sample@sample.com");
        emails.add(email1);
        ScimUser.Email email2 = new ScimUser.Email();
        email2.setValue("");
        emails.add(email2);
        user.setEmails(emails);
        ScimUtils.validate(user);
    }

    @Test(expected = InvalidScimResourceException.class)
    public void userWithEmptyEmail() {
        ScimUser user = new ScimUser(null, "josephine", "Jo", "Jung");
        List<ScimUser.Email> emails = new ArrayList<>();
        ScimUser.Email email = new ScimUser.Email();
        email.setValue("");
        emails.add(email);
        user.setEmails(emails);
        ScimUtils.validate(user);
    }

    @Test(expected = InvalidScimResourceException.class)
    public void userWithNonAsciiUsername() {
        ScimUser user = new ScimUser(null, "joe$eph", "Jo", "User");
        user.setOrigin(OriginKeys.UAA);
        user.addEmail("jo@blah.com");
        ScimUtils.validate(user);
    }

}
