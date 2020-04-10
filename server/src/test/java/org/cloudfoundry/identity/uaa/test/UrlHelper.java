

package org.cloudfoundry.identity.uaa.test;

/**
 * Convenience interface for classes that externalize URLs.
 * 
 * @author Dave Syer
 * 
 */
public interface UrlHelper {

    String getUrl(String path);

    String getBaseUrl();

    String getAccessTokenUri();

    String getAuthorizationUri();

    String getClientsUri();

    String getUsersUri();

    String getUserUri();

}
