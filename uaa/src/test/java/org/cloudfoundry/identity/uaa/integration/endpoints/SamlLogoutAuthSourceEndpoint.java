package org.cloudfoundry.identity.uaa.integration.endpoints;

import org.cloudfoundry.identity.uaa.integration.feature.SamlServerConfig;
import org.cloudfoundry.identity.uaa.integration.pageObjects.SamlWelcomePage;
import org.openqa.selenium.WebDriver;

public class SamlLogoutAuthSourceEndpoint {

    public static SamlWelcomePage assertThatLogoutAuthSource_goesToSamlWelcomePage(WebDriver webDriver, SamlServerConfig samlServerConfig) {
        samlServerConfig.logOut(webDriver);
        return new SamlWelcomePage(webDriver, samlServerConfig);
    }
}
