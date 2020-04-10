package org.cloudfoundry.identity.uaa.login;

public class AutologinResponse {

  private String code;

  public AutologinResponse(String code) {
    this.code = code;
  }

  public String getPath() {
    return "/oauth/authorize";
  }

  public String getCode() {
    return code;
  }
}
