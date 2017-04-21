package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class BrandingInformation implements BrandingInformationSource {
    private String fromAddress;
    private String companyName;
    private String productLogo;
    private String squareLogo;
    private String footerLegalText;
    private Map<String, String> footerLinks;

    public String getFromAddress() {
        return fromAddress;
    }

    public void setFromAddress(String fromAddress) {
        this.fromAddress = fromAddress;
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
}
