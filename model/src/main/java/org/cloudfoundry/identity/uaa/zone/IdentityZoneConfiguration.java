package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import org.cloudfoundry.identity.uaa.login.Prompt;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class IdentityZoneConfiguration {

  private ClientSecretPolicy clientSecretPolicy = new ClientSecretPolicy();
  private TokenPolicy tokenPolicy = new TokenPolicy();
  private SamlConfig samlConfig = new SamlConfig();
  private CorsPolicy corsPolicy = new CorsPolicy();
  private Links links = new Links();
  private List<Prompt> prompts =
      Arrays.asList(
          new Prompt("username", "text", "Email"),
          new Prompt("password", "password", "Password"),
          new Prompt(
              "passcode", "password", "Temporary Authentication Code (Get on at /passcode)"));
  private boolean idpDiscoveryEnabled = false;
  private BrandingInformation branding;
  private boolean accountChooserEnabled;
  private UserConfig userConfig = new UserConfig();
  private MfaConfig mfaConfig = new MfaConfig();
  private String issuer;
  private String defaultIdentityProvider;

  public IdentityZoneConfiguration() {
  }

  public IdentityZoneConfiguration(TokenPolicy tokenPolicy) {
    this.tokenPolicy = tokenPolicy;
  }

  public ClientSecretPolicy getClientSecretPolicy() {
    return clientSecretPolicy;
  }

  public void setClientSecretPolicy(ClientSecretPolicy clientSecretPolicy) {
    this.clientSecretPolicy = clientSecretPolicy;
  }

  public TokenPolicy getTokenPolicy() {
    return tokenPolicy;
  }

  public void setTokenPolicy(TokenPolicy tokenPolicy) {
    this.tokenPolicy = tokenPolicy;
  }

  public SamlConfig getSamlConfig() {
    return samlConfig;
  }

  public IdentityZoneConfiguration setSamlConfig(SamlConfig samlConfig) {
    this.samlConfig = samlConfig;
    return this;
  }

  public Links getLinks() {
    return links;
  }

  public IdentityZoneConfiguration setLinks(Links links) {
    this.links = links;
    return this;
  }

  public List<Prompt> getPrompts() {
    return prompts;
  }

  public IdentityZoneConfiguration setPrompts(List<Prompt> prompts) {
    this.prompts = prompts;
    return this;
  }

  public boolean isIdpDiscoveryEnabled() {
    return idpDiscoveryEnabled;
  }

  public void setIdpDiscoveryEnabled(boolean idpDiscoveryEnabled) {
    this.idpDiscoveryEnabled = idpDiscoveryEnabled;
  }

  public BrandingInformation getBranding() {
    return branding;
  }

  public void setBranding(BrandingInformation branding) {
    this.branding = branding;
  }

  public MfaConfig getMfaConfig() {
    return mfaConfig;
  }

  public IdentityZoneConfiguration setMfaConfig(MfaConfig mfaConfig) {
    this.mfaConfig = mfaConfig;
    return this;
  }

  public CorsPolicy getCorsPolicy() {
    return corsPolicy;
  }

  public IdentityZoneConfiguration setCorsPolicy(CorsPolicy corsPolicy) {
    this.corsPolicy = corsPolicy;
    return this;
  }

  public boolean isAccountChooserEnabled() {
    return accountChooserEnabled;
  }

  public void setAccountChooserEnabled(boolean accountChooserEnabled) {
    this.accountChooserEnabled = accountChooserEnabled;
  }

  public UserConfig getUserConfig() {
    return userConfig;
  }

  public void setUserConfig(UserConfig userConfig) {
    this.userConfig = userConfig;
  }

  public String getDefaultIdentityProvider() {
    return defaultIdentityProvider;
  }

  public void setDefaultIdentityProvider(String defaultIdentityProvider) {
    this.defaultIdentityProvider = defaultIdentityProvider;
  }

  @JsonInclude(JsonInclude.Include.NON_NULL)
  public String getIssuer() {
    return issuer;
  }

  @JsonInclude(JsonInclude.Include.NON_NULL)
  public void setIssuer(String issuer) {
    try {
      new URL(issuer);
      this.issuer = issuer;
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException("Invalid issuer format. Must be valid URL.");
    }
  }
}
