package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.zone.BrandingInformation.Banner;

import java.util.Map;

public interface BrandingInformationSource {
    Banner getBanner();

    String getCompanyName();

    String getProductLogo();

    String getSquareLogo();

    String getFooterLegalText();

    Map<String, String> getFooterLinks();
}
