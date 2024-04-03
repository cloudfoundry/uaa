package org.cloudfoundry.identity.uaa.oauth.provider.endpoint;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;

public class AbstractEndpoint implements InitializingBean {

	protected final Log logger = LogFactory.getLog(getClass());

	private WebResponseExceptionTranslator<OAuth2Exception> providerExceptionHandler = new DefaultWebResponseExceptionTranslator();

	private TokenGranter tokenGranter;

	private ClientDetailsService clientDetailsService;

	private OAuth2RequestFactory oAuth2RequestFactory;

	private OAuth2RequestFactory defaultOAuth2RequestFactory;

	public void afterPropertiesSet() throws Exception {
		defaultOAuth2RequestFactory = new DefaultOAuth2RequestFactory(getClientDetailsService());
		if (oAuth2RequestFactory == null) {
			oAuth2RequestFactory = defaultOAuth2RequestFactory;
		}
	}

	public void setProviderExceptionHandler(WebResponseExceptionTranslator<OAuth2Exception> providerExceptionHandler) {
		this.providerExceptionHandler = providerExceptionHandler;
	}

	public void setTokenGranter(TokenGranter tokenGranter) {
		this.tokenGranter = tokenGranter;
	}

	protected TokenGranter getTokenGranter() {
		return tokenGranter;
	}

	protected WebResponseExceptionTranslator<OAuth2Exception> getExceptionTranslator() {
		return providerExceptionHandler;
	}

	protected OAuth2RequestFactory getOAuth2RequestFactory() {
		return oAuth2RequestFactory;
	}

	protected OAuth2RequestFactory getDefaultOAuth2RequestFactory() {
		return defaultOAuth2RequestFactory;
	}

	public void setOAuth2RequestFactory(OAuth2RequestFactory oAuth2RequestFactory) {
		this.oAuth2RequestFactory = oAuth2RequestFactory;
	}

	protected ClientDetailsService getClientDetailsService() {
		return clientDetailsService;
	}

	public void setClientDetailsService(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

}