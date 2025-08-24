package org.cloudfoundry.identity.uaa.util.beans;

import org.cloudfoundry.identity.uaa.UaaProperties;
import org.cloudfoundry.identity.uaa.home.BuildInfo;

public class TestBuildInfo extends BuildInfo {
    public TestBuildInfo() {
        super(new UaaProperties.Uaa(null));
    }
}
