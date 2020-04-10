package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;
import java.util.Optional;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class Links {

  private SelfService service = new SelfService();
  private Logout logout = new Logout();
  private String homeRedirect = null;

  public Logout getLogout() {
    return logout;
  }

  public Links setLogout(Logout logout) {
    this.logout = logout;
    return this;
  }

  public SelfService getSelfService() {
    return service;
  }

  public Links setSelfService(SelfService service) {
    this.service = service;
    return this;
  }

  public String getHomeRedirect() {
    return homeRedirect;
  }

  public Links setHomeRedirect(String homeRedirect) {
    this.homeRedirect = homeRedirect;
    return this;
  }

  public static class Logout {

    private String redirectUrl = "/login";
    private String redirectParameterName = "redirect";
    private boolean disableRedirectParameter = false;
    private List<String> whitelist = null;

    public boolean isDisableRedirectParameter() {
      return false;
    }

    public Logout setDisableRedirectParameter(boolean disableRedirectParameter) {
      return this;
    }

    public String getRedirectParameterName() {
      return redirectParameterName;
    }

    public Logout setRedirectParameterName(String redirectParameterName) {
      this.redirectParameterName = redirectParameterName;
      return this;
    }

    public String getRedirectUrl() {
      return Optional.ofNullable(redirectUrl).orElse("/login");
    }

    public Logout setRedirectUrl(String redirectUrl) {
      this.redirectUrl = redirectUrl;
      return this;
    }

    public List<String> getWhitelist() {
      return whitelist;
    }

    public Logout setWhitelist(List<String> whitelist) {
      this.whitelist = whitelist;
      return this;
    }
  }

  public static class SelfService {

    private boolean selfServiceLinksEnabled = true;
    private String signup = null;
    private String passwd = null;

    public boolean isSelfServiceLinksEnabled() {
      return selfServiceLinksEnabled;
    }

    public SelfService setSelfServiceLinksEnabled(boolean selfServiceLinksEnabled) {
      this.selfServiceLinksEnabled = selfServiceLinksEnabled;
      return this;
    }

    public String getPasswd() {
      return passwd;
    }

    public SelfService setPasswd(String passwd) {
      this.passwd = passwd;
      return this;
    }

    public String getSignup() {
      return signup;
    }

    public SelfService setSignup(String signup) {
      this.signup = signup;
      return this;
    }
  }
}
