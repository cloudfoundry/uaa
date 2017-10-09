package org.cloudfoundry.identity.uaa.zone;


import org.junit.Before;
import org.junit.Test;

public class ZoneAwareClientSecretPolicyValidatorTests {

    private ZoneAwareClientSecretPolicyValidator validator;

    private IdentityZone zone;

    private ClientSecretPolicy defaultPolicy = new ClientSecretPolicy(0,255,0,0,0,0,6);
    private ClientSecretPolicy strictPolicy = new ClientSecretPolicy(6,10,1,1,1,1,6);

    private static final String TEST_SECRET_1 = "";
    private static final String TEST_SECRET_2 = "testsecret";
    private static final String TEST_SECRET_3 = "VFNTTDEgMB4GA1UEAxMXZnNzLnN0YWdlLmdlY29tcGFueIb3DQEBAQUADDwDG6wkBY" +
            "sJSqbSYpw0c76bUB1x5e46eiroRZdU2BEWiQJ9yxV95gGNsdLH1105iubzc9dbxavGIYM9s/+qJRf6WfwDU7VQsURCqIN8eUtnPU808" +
            "PYjfBA4ucnwJ8wJ8er/8BhRVAfuleAU17WhURSsFZxfan5JxmMadsC+jQohUKiv6SFlPdxuxzuZijVwVgpWOUHO";

    private static final String TEST_SECRET_4 = "Tester1@";
    private static final String TEST_SECRET_5 = "Tester1";
    private static final String TEST_SECRET_6 = "Tester@";
    private static final String TEST_SECRET_7 = "tester@";
    private static final String TEST_SECRET_8 = "TESTER1@";

    @Before
    public void setUp() {
        zone = new IdentityZone();
        IdentityZoneHolder.set(zone);
        validator = new ZoneAwareClientSecretPolicyValidator(defaultPolicy);
    }

    @Test(expected=InvalidClientSecretException.class)
    public void testNullClientSecret() {
        zone.getConfig().setClientSecretPolicy(defaultPolicy);
        validator.validate(null);
    }

    @Test(expected=InvalidClientSecretException.class)
    public void test_defaultPolicyTooLongSecret() {
        zone.getConfig().setClientSecretPolicy(defaultPolicy);
        validator.validate(TEST_SECRET_3);
    }

    @Test
    public void testDefaultPolicy() {
        zone.getConfig().setClientSecretPolicy(defaultPolicy);
        validator.validate(TEST_SECRET_4);
        validator.validate(TEST_SECRET_2);
    }

    @Test
    public void testSecretConformingToPolicy() {
        zone.getConfig().setClientSecretPolicy(strictPolicy);
        validator.validate(TEST_SECRET_4);
    }

    @Test(expected=InvalidClientSecretException.class)
    public void testSecretMissingSpecialCharacter() {
        zone.getConfig().setClientSecretPolicy(strictPolicy);
        validator.validate(TEST_SECRET_5);
    }

    @Test(expected=InvalidClientSecretException.class)
    public void testSecretMissingDigit() {
        zone.getConfig().setClientSecretPolicy(strictPolicy);
        validator.validate(TEST_SECRET_6);
    }

    @Test(expected=InvalidClientSecretException.class)
    public void testSecretMissingUpperCaseCharacter() {
        zone.getConfig().setClientSecretPolicy(strictPolicy);
        validator.validate(TEST_SECRET_7);
    }

    @Test(expected=InvalidClientSecretException.class)
    public void testSecretMissingLowerCaseCharacter() {
        zone.getConfig().setClientSecretPolicy(strictPolicy);
        validator.validate(TEST_SECRET_8);
    }
}