
package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.account.PasswordConfirmationValidation;
import org.junit.Assert;
import org.junit.Test;

public class PasswordConfirmationValidationTest {

    @Test
    public void testValidWithMatchingPasswords() {
        PasswordConfirmationValidation validation = new PasswordConfirmationValidation("secret", "secret");
        Assert.assertTrue(validation.valid());
    }

    @Test
    public void testInvalidWithMismatchedPasswords() {
        PasswordConfirmationValidation validation = new PasswordConfirmationValidation("secret", "mecret");
        Assert.assertFalse(validation.valid());
    }

    @Test
    public void testInvalidWithEmptyPassword() {
        PasswordConfirmationValidation validation = new PasswordConfirmationValidation("", "");
        Assert.assertFalse(validation.valid());
    }
}
