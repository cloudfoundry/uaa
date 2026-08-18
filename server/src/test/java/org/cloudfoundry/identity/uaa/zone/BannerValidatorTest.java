package org.cloudfoundry.identity.uaa.zone;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BannerValidatorTest {
    @Test
    void validatesUrls() throws Exception {
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
    void validateColor() throws Exception {
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
    void base64Logo() throws Exception {
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

    // Additional coverage confirming the JDK-regex-based Base64 validation, which replaced
    // Apache Commons Codec's Base64.isBase64(), still accepts real standard/url-safe/MIME-chunked
    // base64 data and still rejects malformed base64.
    @Test
    void base64LogoAcceptsRealEncodedPayloads() throws Exception {
        byte[] payload = "some banner logo bytes".getBytes(StandardCharsets.UTF_8);
        String[] validBase64 = {
                Base64.getEncoder().encodeToString(payload),
                Base64.getUrlEncoder().encodeToString(payload),
                Base64.getUrlEncoder().withoutPadding().encodeToString(payload),
                Base64.getMimeEncoder().encodeToString(payload),
                "SGVsbG8=",
                "SGVsbG8",
                "SGVsbG-_",
                "SGVsbG8g\nV29ybGQ=",
        };

        for (String base64 : validBase64) {
            BrandingInformation.Banner testBanner = new BrandingInformation.Banner();
            testBanner.setLogo(base64);
            BannerValidator.validate(testBanner);
        }
    }

    @Test
    void base64LogoRejectsMalformedPayloads() {
        String[] invalidBase64 = {
                "SGVsbG8=V29ybGQ=",
                "SGVsbG8===",
                "abc!def",
                "SGVsbG8!",
                "SGVsbG8@#$",
        };

        for (String base64 : invalidBase64) {
            BrandingInformation.Banner testBanner = new BrandingInformation.Banner();
            testBanner.setLogo(base64);
            assertThatThrownBy(() -> BannerValidator.validate(testBanner))
                    .isInstanceOf(InvalidIdentityZoneConfigurationException.class)
                    .hasMessageContaining("Invalid banner logo. Must be in BASE64 format.");
        }
    }
}
