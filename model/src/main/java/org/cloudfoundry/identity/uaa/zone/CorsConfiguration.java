package org.cloudfoundry.identity.uaa.zone;

import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.HttpMethod.GET;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

@JsonIgnoreProperties(ignoreUnknown = true)
public class CorsConfiguration {

  private final List<Pattern> allowedOriginPatterns = new ArrayList<>();
  private final List<Pattern> allowedUriPatterns = new ArrayList<>();
  /**
   * A comma delimited list of regular expression patterns that define which origins are allowed to
   * use the "X-Requested-With" header in CORS requests.
   */
  private List<String> allowedOrigins = Collections.singletonList(".*");
  /**
   * A comma delimited list of regular expression patterns that defines which UAA URIs allow the
   * "X-Requested-With" header in CORS requests.
   */
  private List<String> allowedUris = Collections.singletonList(".*");
  /**
   * A comma delimited list of regular expression patterns that define which origins are allowed to
   * use the "X-Requested-With" header in CORS requests.
   */
  private List<String> allowedHeaders = Arrays.asList(ACCEPT, AUTHORIZATION, CONTENT_TYPE);

  private List<String> allowedMethods = Collections.singletonList(GET.toString());

  private boolean allowedCredentials = false;

  private int maxAge = 1728000;

  public boolean isAllowedCredentials() {
    return allowedCredentials;
  }

  public void setAllowedCredentials(boolean allowedCredentials) {
    this.allowedCredentials = allowedCredentials;
  }

  public List<String> getAllowedHeaders() {
    return allowedHeaders;
  }

  public void setAllowedHeaders(List<String> allowedHeaders) {
    this.allowedHeaders = allowedHeaders;
  }

  public List<String> getAllowedMethods() {
    return allowedMethods;
  }

  public void setAllowedMethods(List<String> allowedMethods) {
    this.allowedMethods = allowedMethods;
  }

  public List<Pattern> getAllowedOriginPatterns() {
    return allowedOriginPatterns;
  }

  public List<String> getAllowedOrigins() {
    return allowedOrigins;
  }

  public void setAllowedOrigins(List<String> allowedOrigins) {
    this.allowedOrigins = allowedOrigins;
  }

  public List<Pattern> getAllowedUriPatterns() {
    return allowedUriPatterns;
  }

  public List<String> getAllowedUris() {
    return allowedUris;
  }

  public void setAllowedUris(List<String> allowedUris) {
    this.allowedUris = allowedUris;
  }

  public int getMaxAge() {
    return maxAge;
  }

  public void setMaxAge(int maxAge) {
    this.maxAge = maxAge;
  }
}
