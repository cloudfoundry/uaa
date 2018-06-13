package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class BrandingInformation implements BrandingInformationSource {
    private String companyName;
    private String productLogo;
    private String squareLogo;
    private String footerLegalText;
    private Map<String, String> footerLinks;
    private Banner banner;
    private Consent consent;

    public Banner getBanner() {
        return banner;
    }

    public void setBanner(Banner banner) {
        this.banner = banner;
    }

    @Override
    public String getCompanyName() {
        return companyName;
    }

    public void setCompanyName(String companyName) {
        this.companyName = companyName;
    }

    @Override
    public String getProductLogo() {
        return productLogo;
    }

    public void setProductLogo(String productLogo) {
        this.productLogo = productLogo;
    }

    @Override
    public String getSquareLogo() {
        return squareLogo;
    }

    public void setSquareLogo(String squareLogo) {
        this.squareLogo = squareLogo;
    }

    @Override
    public String getFooterLegalText() {
        return footerLegalText;
    }

    public void setFooterLegalText(String footerLegalText) {
        this.footerLegalText = footerLegalText;
    }

    @Override
    public Map<String, String> getFooterLinks() {
        return footerLinks;
    }

    public void setFooterLinks(Map<String, String> footerLinks) {
        this.footerLinks = footerLinks;
    }

    public void setConsent(Consent consent) {
        this.consent = consent;
    }

    public Consent getConsent() {
        return consent;
    }

    public static class Banner {
        String logo;
        String text;
        String textColor;
        String backgroundColor;
        String link;

        public void setLogo(String logo) {
            this.logo = logo;
        }

        public void setText(String text) {
            this.text = text;
        }

        public void setTextColor(String textColor) {
            this.textColor = textColor;
        }

        public void setBackgroundColor(String backgroundColor) {
            this.backgroundColor = backgroundColor;
        }

        public void setLink(String link) {
            this.link = link;
        }

        public String getLogo() {
            return logo;
        }

        public String getText() {
            return text;
        }

        public String getTextColor() {
            return textColor;
        }

        public String getBackgroundColor() {
            return backgroundColor;
        }

        public String getLink() {
            return link;
        }
    }
}
