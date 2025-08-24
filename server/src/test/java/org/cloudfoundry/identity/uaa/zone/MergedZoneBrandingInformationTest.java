package org.cloudfoundry.identity.uaa.zone;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;

class MergedZoneBrandingInformationTest {

    private BrandingInformation zoneBranding;
    private BrandingInformation defaultZoneBranding;
    private IdentityZone fakeUaa;

    @BeforeEach
    void setUp() {
        defaultZoneBranding = new BrandingInformation();
        final String productLogo = getResourceAsString(getClass(), "IdentityZoneHolderTest_ProductLogo");
        defaultZoneBranding.setProductLogo(productLogo);

        zoneBranding = new BrandingInformation();
        zoneBranding.setProductLogo("zoneBrandingString===");

        fakeUaa = IdentityZoneHolder.getUaaZone();
        fakeUaa.getConfig().setBranding(defaultZoneBranding);

        IdentityZoneProvisioning provisioning = Mockito.mock(IdentityZoneProvisioning.class);
        IdentityZoneHolder.setProvisioning(provisioning);

        Mockito.when(provisioning.retrieve(fakeUaa.getId())).thenReturn(fakeUaa);
    }

    @Test
    void getProductLogoForZone() {
        IdentityZone testZone = new IdentityZone();
        IdentityZoneHolder.set(testZone);
        IdentityZoneHolder.get().getConfig().setBranding(zoneBranding);

        BrandingInformationSource brandingInformationSource = MergedZoneBrandingInformation.resolveBranding();
        assertThat(zoneBranding.getProductLogo()).isEqualTo(brandingInformationSource.getProductLogo());
    }

    @Test
    void emptyProductLogoForZoneDoesNotReturnDefault() {
        IdentityZone testZone = new IdentityZone();
        IdentityZoneHolder.set(testZone);
        IdentityZoneHolder.get().getConfig().setBranding(new BrandingInformation());

        BrandingInformationSource brandingInformationSource = MergedZoneBrandingInformation.resolveBranding();
        assertThat(brandingInformationSource.getProductLogo()).isNull();
    }

    @Test
    void getProductLogoForDefaultZoneReturnsDefaultLogo() {
        IdentityZoneHolder.set(fakeUaa);

        BrandingInformationSource brandingInformationSource = MergedZoneBrandingInformation.resolveBranding();
        assertThat(defaultZoneBranding.getProductLogo()).isEqualTo(brandingInformationSource.getProductLogo());
    }
}