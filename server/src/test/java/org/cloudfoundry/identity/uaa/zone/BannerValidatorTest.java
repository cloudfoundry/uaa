package org.cloudfoundry.identity.uaa.zone;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BannerValidatorTest {
    @Test
    void validatesUrls() throws InvalidIdentityZoneConfigurationException {
        String[] validUrls = {
                "https://example.com",
                "https://example.com/",
                "http://example.com/",
                "ftp://example.com/",
                "https://example.com?",
                "https://example.com?a=b",
                "https://example.com?a=b&c=d",
                "https://example.com/?a=b",
                "https://example.com/some/path",
                "https://example.com#fragment",
                "https://example.io",
                "https://example.longtld",
                "https://subdomain.example.com",
                "https://subdomain.example.com",
                "https://example.co.uk",
                "https://example",
                "http://224.1.1.1 ",
                "http://127.0.0.1",
        };

        String[] invalidUrls = {
                "example",
                "example.com",
                "example.com:666",
                "// ",
                "//a",
                "///a ",
                "///",
                "rdar://1234",
                "h://test ",
                ":// should fail",
                "ftps://foo.bar/",
        };

        for (String url : validUrls) {
            BrandingInformation.Banner testBanner = new BrandingInformation.Banner();
            testBanner.setLink(url);
            BannerValidator.validate(testBanner);
        }

        for (String url : invalidUrls) {
            BrandingInformation.Banner testBanner = new BrandingInformation.Banner();
            testBanner.setLink(url);
            assertThatThrownBy(() -> BannerValidator.validate(testBanner))
                    .isInstanceOf(InvalidIdentityZoneConfigurationException.class)
                    .hasMessageContaining("Invalid banner link: " + url + ". Must be a properly formatted URI beginning with http:// or https://");
        }
    }

    @Test
    void validateColor() throws InvalidIdentityZoneConfigurationException {
        String[] validColors = {
                "#123456",
                "#000",
                "#DEDBEF",
                "#b0dc8a"
        };

        String[] invalidColors = {
                "#00",
                "#12345",
                "F123",
                "red",
                "cyan",
        };

        for (String color : validColors) {
            BrandingInformation.Banner testBanner = new BrandingInformation.Banner();
            testBanner.setTextColor(color);
            testBanner.setBackgroundColor(color);
            BannerValidator.validate(testBanner);
        }

        for (String color : invalidColors) {
            BrandingInformation.Banner testBanner = new BrandingInformation.Banner();
            testBanner.setTextColor(color);

            assertThatThrownBy(() -> BannerValidator.validate(testBanner))
                    .isInstanceOf(InvalidIdentityZoneConfigurationException.class)
                    .hasMessageContaining("Invalid banner text color: " + color + ". Must be a properly formatted hexadecimal color code.");
        }

        for (String color : invalidColors) {
            BrandingInformation.Banner testBanner = new BrandingInformation.Banner();
            testBanner.setBackgroundColor(color);

            assertThatThrownBy(() -> BannerValidator.validate(testBanner))
                    .isInstanceOf(InvalidIdentityZoneConfigurationException.class)
                    .hasMessageContaining("Invalid banner background color: " + color + ". Must be a properly formatted hexadecimal color code.");
        }
    }

    @Test
    void base64Logo() throws InvalidIdentityZoneConfigurationException {
        String[] validBase64 = {
                "BIPUQGEWGPIUB64",
                ""
        };
        String[] invalidBase64 = {
                "%%%%%",
                "~45234"
        };

        for (String base64 : validBase64) {
            BrandingInformation.Banner testBanner = new BrandingInformation.Banner();
            testBanner.setLogo(base64);
            BannerValidator.validate(testBanner);
        }

        for (String base64 : invalidBase64) {
            BrandingInformation.Banner testBanner = new BrandingInformation.Banner();
            testBanner.setLogo(base64);
            assertThatThrownBy(() -> BannerValidator.validate(testBanner))
                    .isInstanceOf(InvalidIdentityZoneConfigurationException.class)
                    .hasMessageContaining("Invalid banner logo. Must be in BASE64 format.");
        }
    }
}
