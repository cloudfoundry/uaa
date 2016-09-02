package org.cloudfoundry.identity.uaa.zone;

import java.util.Map;

public interface BrandingInformationSource {
    String getCompanyName();

    String getProductLogo();

    String getSquareLogo();

    String getFooterLegalText();

    Map<String, String> getFooterLinks();
}
