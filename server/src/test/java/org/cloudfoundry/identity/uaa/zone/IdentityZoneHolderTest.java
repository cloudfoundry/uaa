package org.cloudfoundry.identity.uaa.zone;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class IdentityZoneHolderTest {

  private BrandingInformation zoneBranding;
  private BrandingInformation defaultZoneBranding;
  private IdentityZone fakeUaa;

  @Before
  public void setUp() throws Exception {
    defaultZoneBranding = new BrandingInformation();
    defaultZoneBranding.setProductLogo("iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAABSUlEQVQ4EaVTO04DMRB9YdOTC+QcK46w" +
      "FU3apclKuQMH4AYUkUxFmyY0PgLac3AB6ImM3kyePYkQDZZ27Zl58+aNP8A/x2J7ixI5Xr6wiHaMX8eIW/L3/tlStisUAZm8fx1acMxWTPFK0BBOR" +
      "hL5ukP2ZQ9UsjHXIqZA4LuVrwjsPjxxenRfAtAh47QenCiQgFL5fb8NpTyjlAf/5KOfa/llk/pG1WvV2T3T0We1wLh8jNAmaSUwyTMMRGC6dxDXIl" +
      "ExtUd7SZb0BKhXU3LIRrTfKKXNpsLU+R7VTWTFKJEpuzGbktNmuFiLjnEj4M52s4OnMVt/CedTYLWjx9Artc1269hG3MSohMps9LAjVCqrc9QWaJg" +
      "SZCRWOp+GoX5J5u3lvan3nioIphIOnQr711BVXf0LAoGuieRnMt8A438SKEFEsuMDirEf/oirUgza/ucAAAAASUVORK5CYII=");

    zoneBranding = new BrandingInformation();
    zoneBranding.setProductLogo("zoneBrandingString===");

    fakeUaa = IdentityZoneHolder.getUaaZone();
    fakeUaa.getConfig().setBranding(defaultZoneBranding);

    IdentityZoneProvisioning provisioning = Mockito.mock(IdentityZoneProvisioning.class);
    IdentityZoneHolder.setProvisioning(provisioning);

    Mockito.when(provisioning.retrieve(fakeUaa.getId())).thenReturn(fakeUaa);
  }

  @Test
  public void getProductLogoForZone() {
    IdentityZone testZone = new IdentityZone();
    IdentityZoneHolder.set(testZone);
    IdentityZoneHolder.get().getConfig().setBranding(zoneBranding);

    BrandingInformationSource brandingInformationSource = IdentityZoneHolder.resolveBranding();
    assertEquals(brandingInformationSource.getProductLogo(), zoneBranding.getProductLogo());
  }

  @Test
  public void emptyProductLogoForZoneDoesNotReturnDefault() {
    IdentityZone testZone = new IdentityZone();
    IdentityZoneHolder.set(testZone);
    IdentityZoneHolder.get().getConfig().setBranding(new BrandingInformation());

    BrandingInformationSource brandingInformationSource = IdentityZoneHolder.resolveBranding();
    assertNull(brandingInformationSource.getProductLogo());
  }

  @Test
  public void getProductLogoForDefaultZoneReturnsDefaultLogo() {
    IdentityZoneHolder.set(fakeUaa);

    BrandingInformationSource brandingInformationSource = IdentityZoneHolder.resolveBranding();
    assertEquals(brandingInformationSource.getProductLogo(), defaultZoneBranding.getProductLogo());
  }
}
