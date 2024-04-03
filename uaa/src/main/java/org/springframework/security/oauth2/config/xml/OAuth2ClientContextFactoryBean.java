package org.springframework.security.oauth2.config.xml;

import org.cloudfoundry.identity.uaa.oauth.client.OAuth2ClientContext;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
public class OAuth2ClientContextFactoryBean implements FactoryBean<OAuth2ClientContext> {

	private OAuth2ProtectedResourceDetails resource;

	private OAuth2ClientContext bareContext;

	private OAuth2ClientContext scopedContext;
	
	/**
	 * @param resource the resource to set
	 */
	public void setResource(OAuth2ProtectedResourceDetails resource) {
		this.resource = resource;
	}

	/**
	 * @param scopedContext the scopedContext to set
	 */
	public void setScopedContext(OAuth2ClientContext scopedContext) {
		this.scopedContext = scopedContext;
	}

	/**
	 * @param bareContext the bareContext to set
	 */
	public void setBareContext(OAuth2ClientContext bareContext) {
		this.bareContext = bareContext;
	}

	public OAuth2ClientContext getObject() throws Exception {
		if (resource instanceof ClientCredentialsResourceDetails) {
			return bareContext;
		}
		return scopedContext;
	}

	public Class<?> getObjectType() {
		return OAuth2ClientContext.class;
	}

	public boolean isSingleton() {
		return true;
	}

}
