package org.cloudfoundry.identity.uaa.zone;

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation.Banner;
import org.springframework.util.StringUtils;

import java.util.regex.Pattern;

public class BannerValidator {
    private static final Pattern hexColorPattern = Pattern.compile("^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$");

    public static void validate(Banner banner) throws InvalidIdentityZoneConfigurationException {
        if (banner != null) {
            if (StringUtils.hasText(banner.getLink())) {
                if (!UaaUrlUtils.isUrl(banner.getLink())) {
                    throw new InvalidIdentityZoneConfigurationException("Invalid banner link: " + banner.getLink() + ". Must be a properly formatted URI beginning with http:// or https://", null);
                }
            }
            if (StringUtils.hasText(banner.getBackgroundColor())) {
                if (!hexColorPattern.matcher(banner.getBackgroundColor()).matches()) {
                    throw new InvalidIdentityZoneConfigurationException("Invalid banner background color: " + banner.getBackgroundColor() + ". Must be a properly formatted hexadecimal color code.", null);
                }
            }
            if (StringUtils.hasText(banner.getTextColor())) {
                if (!hexColorPattern.matcher(banner.getTextColor()).matches()) {
                    throw new InvalidIdentityZoneConfigurationException("Invalid banner text color: " + banner.getTextColor() + ". Must be a properly formatted hexadecimal color code.", null);
                }
            }
            if (StringUtils.hasText(banner.getLogo())) {
                if (!Base64.isBase64(banner.getLogo())) {
                    throw new InvalidIdentityZoneConfigurationException("Invalid banner logo. Must be in BASE64 format.", null);
                }
            }
        }
    }
}
