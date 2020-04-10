package org.cloudfoundry.identity.uaa.zone;

import java.util.Map;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation.Banner;

public interface BrandingInformationSource {

  Banner getBanner();

  String getCompanyName();

  String getProductLogo();

  String getSquareLogo();

  String getFooterLegalText();

  Map<String, String> getFooterLinks();
}
