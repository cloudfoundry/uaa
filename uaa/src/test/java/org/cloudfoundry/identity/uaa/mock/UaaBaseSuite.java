package org.cloudfoundry.identity.uaa.mock;

import org.junit.AfterClass;
import org.junit.BeforeClass;

public class UaaBaseSuite {
    private static volatile boolean suiteActive = false;

    /**
     *
     * @return false if the test has been invoked within gradle (based on system property)
     * and the test is not running while the test suite is running.
     */
    public static boolean shouldMockTestBeRun() {
        boolean gradle = Boolean.valueOf(System.getProperty("mock.suite.test"));
        if (gradle) {
            return suiteActive;
        } else {
            return true;
        }
    }

    @BeforeClass
    public static void suiteIsActive() {
        suiteActive = true;
    }

    @AfterClass
    public static void suiteIsNotActive() {
        suiteActive = false;
    }


}
