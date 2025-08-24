package org.cloudfoundry.identity.uaa.test;

import org.cloudfoundry.identity.uaa.oauth.client.test.TestAccounts;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.test.UaaTestAccounts.UAA_TEST_PASSWORD;
import static org.cloudfoundry.identity.uaa.test.UaaTestAccounts.UAA_TEST_USERNAME;

class UaaTestAccountsTest {

    private TestAccounts testAccounts;
    private String originalUaaTestUsername;
    private String originalUaaTestPassword;

    @BeforeEach
    void setUp() {
        testAccounts = UaaTestAccounts.standard(null);
        originalUaaTestUsername = System.getProperty(UAA_TEST_USERNAME);
        originalUaaTestPassword = System.getProperty(UAA_TEST_PASSWORD);
    }

    @AfterEach
    void restoreProperties() {
        if (originalUaaTestUsername == null) {
            System.clearProperty(UAA_TEST_USERNAME);
        } else {
            System.setProperty(UAA_TEST_USERNAME, originalUaaTestUsername);
        }
        if (originalUaaTestPassword == null) {
            System.clearProperty(UAA_TEST_PASSWORD);
        } else {
            System.setProperty(UAA_TEST_PASSWORD, originalUaaTestPassword);
        }
    }

    @Test
    void getDefaultUsername() {
        assertThat(testAccounts.getUserName()).isEqualTo(UaaTestAccounts.DEFAULT_USERNAME);
    }

    @Test
    void getAlternateUsername() {
        String username = "marissa2";
        System.setProperty(UAA_TEST_USERNAME, username);
        assertThat(testAccounts.getUserName()).isEqualTo(username);
    }

    @Test
    void getDefaultPassword() {
        assertThat(testAccounts.getPassword()).isEqualTo(UaaTestAccounts.DEFAULT_PASSWORD);
    }

    @Test
    void getAlternatePassword() {
        String password = "koala2";
        System.setProperty(UAA_TEST_PASSWORD, password);
        assertThat(testAccounts.getPassword()).isEqualTo(password);
    }
}
