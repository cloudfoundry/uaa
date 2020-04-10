package org.cloudfoundry.identity.uaa.client;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.net.URL;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ClientMetadata {

  private String clientId;
  private String clientName;
  private String identityZoneId;
  private boolean showOnHomePage;
  private URL appLaunchUrl;
  private String appIcon;
  private String createdBy;

  public String getClientId() {
    return clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  @JsonIgnore
  public String getIdentityZoneId() {
    return identityZoneId;
  }

  @JsonIgnore
  public void setIdentityZoneId(String identityZoneId) {
    this.identityZoneId = identityZoneId;
  }

  public boolean isShowOnHomePage() {
    return showOnHomePage;
  }

  public void setShowOnHomePage(boolean showOnHomePage) {
    this.showOnHomePage = showOnHomePage;
  }

  public URL getAppLaunchUrl() {
    return appLaunchUrl;
  }

  public void setAppLaunchUrl(URL appLaunchUrl) {
    this.appLaunchUrl = appLaunchUrl;
  }

  public String getAppIcon() {
    return appIcon;
  }

  public void setAppIcon(String appIcon) {
    this.appIcon = appIcon;
  }

  public String getClientName() {
    return clientName;
  }

  public void setClientName(String clientName) {
    this.clientName = clientName;
  }

  public String getCreatedBy() {
    return createdBy;
  }

  public ClientMetadata setCreatedBy(String createdBy) {
    this.createdBy = createdBy;
    return this;
  }
}
