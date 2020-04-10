package org.cloudfoundry.identity.uaa.zone;

import static java.util.Optional.ofNullable;

import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

public class MergedZoneBrandingInformation implements BrandingInformationSource {

  private static final BrandingInformationSource singleton = new MergedZoneBrandingInformation();

  private MergedZoneBrandingInformation() {}

  public static BrandingInformationSource resolveBranding() {
    return singleton;
  }

  private static <T> T resolve(Function<BrandingInformationSource, T> brandingProperty) {
    return tryGet(IdentityZoneHolder.get(), brandingProperty)
        .orElse(tryGet(IdentityZoneHolder.getUaaZone(), brandingProperty).orElse(null));
  }

  private static <T> Optional<T> tryGet(
      IdentityZone zone, Function<BrandingInformationSource, T> brandingProperty) {
    return ofNullable(zone.getConfig())
        .flatMap(c -> ofNullable(c.getBranding()))
        .flatMap(b -> ofNullable(brandingProperty.apply(b)));
  }

  @Override
  public BrandingInformation.Banner getBanner() {
    return resolve(BrandingInformationSource::getBanner);
  }

  @Override
  public String getCompanyName() {
    return resolve(BrandingInformationSource::getCompanyName);
  }

  @Override
  public String getProductLogo() {
    return tryGet(IdentityZoneHolder.get(), BrandingInformationSource::getProductLogo).orElse(null);
  }

  @Override
  public String getSquareLogo() {
    return resolve(BrandingInformationSource::getSquareLogo);
  }

  @Override
  public String getFooterLegalText() {
    return resolve(BrandingInformationSource::getFooterLegalText);
  }

  @Override
  public Map<String, String> getFooterLinks() {
    return resolve(BrandingInformationSource::getFooterLinks);
  }
}
