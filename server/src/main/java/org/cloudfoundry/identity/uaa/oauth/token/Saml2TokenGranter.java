/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] SAP SE. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.oauth.token;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.openssl.PEMReader;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.DisallowedIdpException;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSamlAuthenticationProvider;
import org.cloudfoundry.identity.uaa.provider.saml.ZoneAwareMetadataGenerator;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SSODescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.impl.SingleSignOnServiceBuilder;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.CollectionCredentialResolver;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.UnauthorizedClientException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.saml.SAMLAuthenticationToken;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataManager;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class Saml2TokenGranter extends AbstractTokenGranter {

	@SuppressWarnings("unused")
	private RevocableTokenProvisioning tokenStore;
	private LoginSamlAuthenticationProvider samlAuthenticationProvider;
	private ZoneAwareMetadataGenerator metazone;
	private MetadataManager metadata;
	private IdentityProviderProvisioning identityProviderProvisioning;
	private final Log logger = LogFactory.getLog(getClass());

	public void setMetadata(MetadataManager metadata) {
		this.metadata = metadata;
	}

	public void setMetazone(ZoneAwareMetadataGenerator metazone) {
		this.metazone = metazone;
	}

	public void setSamlAuthenticationProvider(LoginSamlAuthenticationProvider samlAuthenticationProvider) {
		this.samlAuthenticationProvider = samlAuthenticationProvider;
	}

	public void setIdentityProviderProvisioning(IdentityProviderProvisioning identityProviderProvisioning) {
		this.identityProviderProvisioning = identityProviderProvisioning;
	}

	public Saml2TokenGranter(AuthorizationServerTokenServices tokenServices, ClientDetailsService clientDetailsService,
			OAuth2RequestFactory requestFactory, RevocableTokenProvisioning tokenStore) {
		super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE_SAML2_BEARER);
		this.tokenStore = tokenStore;
	}

	@Override
	public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
		TokenRequest adjusted = new TokenRequest(tokenRequest.getRequestParameters(), tokenRequest.getClientId(),
				tokenRequest.getScope(), tokenRequest.getGrantType());
		return super.grant(grantType, adjusted);
	}

	@Override
	protected OAuth2RequestFactory getRequestFactory() {
		return super.getRequestFactory();
	}

	@Override
	protected void validateGrantType(String grantType, ClientDetails clientDetails) {
		if (!GRANT_TYPE_SAML2_BEARER.equals(grantType)) {
			throw new InvalidClientException("Invalid grant type");
		}
		if (clientDetails.getAuthorizedGrantTypes().contains(grantType) == false) {
			throw new InvalidClientException("Client " + clientDetails.getClientId() + " has not authorized grant type: " + GRANT_TYPE_SAML2_BEARER);
		}
	}

	@SuppressWarnings("unchecked")
	protected Authentication validateRequest(TokenRequest request) {
		// things to validate
		if(request == null || request.getRequestParameters() == null)
			throw new InvalidGrantException("Invalid token requst object");
		if(request.getRequestParameters().get("grant_type") == null)
			throw new InvalidGrantException("Invalid grant type");
		// parse the XML to Assertion
		Assertion assertion = null;
		try {
			String assertionParameter = request.getRequestParameters().get("assertion");
			if(assertionParameter == null) {
				logger.debug("Missing assertion in token requst");
				throw new InvalidGrantException("Missing assertion in token requst");
			}
			if(logger.isDebugEnabled()) {
				logger.debug("saml-bearer message: " + assertionParameter);
			}
			assertion = (Assertion)unmarshallAssertion(assertionParameter);
		} catch ( UnmarshallingException | XMLParserException | UnsupportedEncodingException e) {
			logger.debug("Invalid authentication object: " + e.getMessage());
			throw new InvalidGrantException("Invalid authentication object", e);
		}
		/*
		 * Create SAML message context from Assertion object
		 * Thus we are not in WebSSOProfile we do not have the message context available
		 * but we create it and fill the most needed stuff into
		 */
		SAMLMessageContext context = createMessageObject(assertion);
		/*
		 * Create the SAMLAuthenticationToken from the SAMLMessageContext
		 * This allows to call the authenticate method, which performs the
		 * authentication of the SAML2 message. So we re-use the existing SAMl2
		 * authentication for SAML2 bearer flow. This makes sense because it needs
		 * the same checks
		 */
		SAMLAuthenticationToken token = new SAMLAuthenticationToken(context);
		if (samlAuthenticationProvider != null)
			return samlAuthenticationProvider.authenticate(token);
		else
			throw new InsufficientAuthenticationException("Invalid authentication object");
	}

	@Override
	protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
		Authentication userAuth = validateRequest(tokenRequest);
		/* from now the User is authenticated.
		 * compared to authorization grant the resource Id is not yet filled, and other checks, e.g. allowed providers
		 * are implemented directly in UaaAuthorizationRequestManager, so we copied it because they cannot be reused from there 
		 */
		// TODO refactor saml-bearer and authorization request manager
		if (userAuth instanceof UaaAuthentication && client instanceof BaseClientDetails) {
			BaseClientDetails clientDetails = (BaseClientDetails) client;
			UaaPrincipal uaaPrincipal = (UaaPrincipal) userAuth.getPrincipal();
			UaaAuthentication uaaAuth = (UaaAuthentication) userAuth;
			Collection<? extends GrantedAuthority> authorities = uaaAuth.getAuthorities();
			// validate scopes
			Set<String> scopes = checkUserScopes(clientDetails.getScope(), authorities, clientDetails);
			tokenRequest.setScope(scopes);
			// check client IDP relationship - allowed providers
			checkClientIdpAuthorization(clientDetails, uaaPrincipal);
			Set<String> resourceIds = getResourceIds(clientDetails, scopes);
			clientDetails.setResourceIds(resourceIds);
		}
		else
		{
			logger.warn("Invalid authentication object");
		}
		OAuth2Request storedOAuth2Request = getRequestFactory().createOAuth2Request(client, tokenRequest);
		logger.info("SAML2 bearer validation succeeded");
		return new OAuth2Authentication(storedOAuth2Request, userAuth);
	}

	@Override
	protected OAuth2AccessToken getAccessToken(ClientDetails client, TokenRequest tokenRequest) {
		return super.getAccessToken(client, tokenRequest);
	}

	/*
	 * Create SAML message context from Assertion object
	 * Thus we are not in WebSSOProfile we do not have the message context available
	 * but we create it and fill the most needed stuff into
	 */
	private SAMLMessageContext createMessageObject(Assertion assertion) {
		String assertionIssuer = null;
		SAMLMessageContext context = new SAMLMessageContext();
		ExtendedMetadata idpMetadata = null;
		ExtendedMetadata spsMetadata = null;
		EntityDescriptor idpDescriptor = null;
		EntityDescriptor spsDescriptor = null;
		if(assertion != null && assertion.getIssuer() != null) {
			assertionIssuer = assertion.getIssuer().getValue();
		}
		if(assertionIssuer == null || assertionIssuer.trim().length() == 0) {
			throw new InsufficientAuthenticationException("Missing issuer in assertion object");
		}
		/* retrieve information from zoneAwareMetadataGenerator bean */
		try {
			idpMetadata = this.metadata.getExtendedMetadata(assertionIssuer);
			spsMetadata = this.metazone.getExtendedMetadata();
			idpDescriptor = this.metadata.getEntityDescriptor(assertionIssuer);
			spsDescriptor = this.metadata.getEntityDescriptor(this.metazone.getEntityId());
		} catch (MetadataProviderException e1) {
			throw new InsufficientAuthenticationException("Invalid authentication object", e1);
		}
		// build Response and wrap the Assertion into as work around for spring security
		Response samlResponse = wrapAssertionIntoResponse(assertion, assertionIssuer);
		context.setInboundMessage(samlResponse);
		context.setInboundSAMLMessage(samlResponse);
		context.setLocalExtendedMetadata(spsMetadata);
		context.setLocalEntityMetadata(spsDescriptor);
		context.setLocalEntityId(UaaUrlUtils.getUaaUrl("/oauth/token"));
		context.setPeerExtendedMetadata(idpMetadata);
		context.setPeerEntityMetadata(idpDescriptor);
		context.setCommunicationProfileId(SAMLConstants.SAML2_WEBSSO_PROFILE_URI);
		SPSSODescriptor localRole = spsDescriptor.getSPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");
		localRole.setWantAssertionsSigned(true);
		context.setLocalEntityRoleMetadata(localRole);
		/*  */
		context.setLocalEntityEndpoint(buildLocalEndpoint(UaaUrlUtils.getUaaUrl("/oauth/token")));
		/* signature verification .... */
		context.setLocalTrustEngine(getTrustEngine(idpDescriptor));
		return context;
	}
	/*
	 * Unmarshall XML string to OpenSAML XMLObject
	 */
	private XMLObject unmarshallAssertion(String xmlString) throws UnmarshallingException, XMLParserException, UnsupportedEncodingException {
		BasicParserPool parser = new BasicParserPool();
		parser.setNamespaceAware(true);
		/* Base64URL encoded */
		byte bytes[] = Base64.decodeBase64(xmlString);
		if (bytes == null || bytes.length == 0)
			throw new InsufficientAuthenticationException("Invalid assertion encoding");
		Reader reader = new InputStreamReader(new ByteArrayInputStream(bytes), "utf-8");
		Document doc = parser.parse(reader);
		Element samlElement = doc.getDocumentElement();

		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(samlElement);
		return unmarshaller.unmarshall(samlElement);
	}
	/*
	 * Build Endpoint object for SAML message context
	 */
	private Endpoint buildLocalEndpoint(String entityBaseURL) {
		SingleSignOnService sso = new SingleSignOnServiceBuilder().buildObject();
		sso.setLocation(entityBaseURL);
		sso.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
		return sso;
	}
	/*
	 * Create SignatureTrustEngine object for SAML message context
	 * Reuse the certificate from current IdpDescriptor from MetadataManager
	 */
	private SignatureTrustEngine getTrustEngine(EntityDescriptor idpDesc) {
		PEMReader reader;
		List<Credential> credentials = new ArrayList<Credential>();
		SSODescriptor desriptor =  idpDesc.getIDPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");
		if(desriptor == null) desriptor = idpDesc.getSPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");
		if(desriptor != null) {
			for (KeyDescriptor keydesc : desriptor.getKeyDescriptors()) {
				for (org.opensaml.xml.signature.X509Data x509data : keydesc.getKeyInfo().getX509Datas()) {
					for (org.opensaml.xml.signature.X509Certificate x509cert : x509data.getX509Certificates()) {
						try {
							BasicX509Credential xcredential = new BasicX509Credential();
							X509Certificate cert;
							StringBuffer sb = new StringBuffer("-----BEGIN CERTIFICATE-----\n")
															.append(x509cert.getValue())
															.append("\n-----END CERTIFICATE-----");
							reader = new PEMReader(
									new InputStreamReader(new ByteArrayInputStream(sb.toString().getBytes("utf-8")), "utf-8"));
							cert = (X509Certificate) reader.readObject();
							if (cert != null) {
								xcredential.setEntityCertificate(cert);
								credentials.add(xcredential);
							} else  {
								reader.close();
								throw new IOException("Invalid key");
							}
						} catch (IOException ex) {
							continue;
						}
					}
				}
			}
		}
		if(credentials.isEmpty()) {
			throw new InsufficientAuthenticationException("Invalid remote IDP object: missing X509Certificate");
		}
		CollectionCredentialResolver credResolver = new CollectionCredentialResolver(credentials);
		KeyInfoCredentialResolver kiResolver = SecurityHelper.buildBasicInlineKeyInfoResolver();
		return new ExplicitKeySignatureTrustEngine(credResolver, kiResolver);
	}
	/*
	 * Copied this methods from org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationRequestManager
	 */
	private final Map<String, String> scopeToResource = Collections.singletonMap("openid", "openid");
	private final String scopeSeparator = ".";
	private Set<String> getResourceIds(ClientDetails clientDetails, Set<String> scopes) {
		Set<String> resourceIds = new LinkedHashSet<String>();
		// at a minimum - the resourceIds should contain the client this is
		// intended for
		// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
		if (clientDetails.getClientId() != null) {
			resourceIds.add(clientDetails.getClientId());
		}
		for (String scope : scopes) {
			if (scopeToResource.containsKey(scope)) {
				resourceIds.add(scopeToResource.get(scope));
			} else if (scope.contains(scopeSeparator) && !scope.endsWith(scopeSeparator) && !scope.equals("uaa.none")) {
				String id = scope.substring(0, scope.lastIndexOf(scopeSeparator));
				resourceIds.add(id);
			}
		}
		return resourceIds.isEmpty() ? clientDetails.getResourceIds() : resourceIds;
	}
	/*
	 * Copied this methods from org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationRequestManager
	 */
	private void checkClientIdpAuthorization(BaseClientDetails client, UaaPrincipal user) {
		List<String> allowedProviders = (List<String>) client.getAdditionalInformation().get(ClientConstants.ALLOWED_PROVIDERS);
		if (allowedProviders == null) {
			// null means any providers - no allowed providers means that we
			// always allow it (backwards compatible)
			return;
		} else if (allowedProviders.isEmpty()) {
			throw new UnauthorizedClientException("Client is not authorized for any identity providers.");
		}

		try {
			IdentityProvider<?> provider = identityProviderProvisioning.retrieveByOrigin(user.getOrigin(), user.getZoneId());
			if (provider == null || !allowedProviders.contains(provider.getOriginKey())) {
				throw new DisallowedIdpException("Client is not authorized for specified user's identity provider.");
			}
		} catch (EmptyResultDataAccessException x) {
			// this should not happen...but if it does
			throw new UnauthorizedClientException("User does not belong to a valid identity provider.", x);
		}
	}
	/*
	 * Copied this methods from org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationRequestManager
	 */
	private Set<String> checkUserScopes(Set<String> requestedScopes, Collection<? extends GrantedAuthority> authorities,
			ClientDetails clientDetails) {
		Set<String> allowed = new LinkedHashSet<>(AuthorityUtils.authorityListToSet(authorities));

		// Find intersection of user authorities, default requestedScopes and
		// client requestedScopes:
		Set<String> result = intersectScopes(new LinkedHashSet<>(requestedScopes), clientDetails.getScope(), allowed);

		// Check that a token with empty scope is not going to be granted
		if (result.isEmpty() && !clientDetails.getScope().isEmpty()) {
			throw new InvalidScopeException(
					"Invalid scope (empty) - this user is not allowed any of the requested scopes: " + requestedScopes
							+ " (either you requested a scope that was not allowed or client '"
							+ clientDetails.getClientId() + "' is not allowed to act on behalf of this user)",
					allowed);
		}

		return result;
	}
	/*
	 * Copied this methods from org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationRequestManager
	 */
	private Set<String> intersectScopes(Set<String> requestedScopes, Set<String> clientScopes, Set<String> userScopes) {
		Set<String> result = new HashSet<>(userScopes);

		Set<Pattern> clientWildcards = constructWildcards(clientScopes);
		for (Iterator<String> iter = result.iterator(); iter.hasNext();) {
			String scope = iter.next();
			if (!matches(clientWildcards, scope)) {
				iter.remove();
			}
		}

		Set<Pattern> requestedWildcards = constructWildcards(requestedScopes);
		// Weed out disallowed requestedScopes:
		for (Iterator<String> iter = result.iterator(); iter.hasNext();) {
			String scope = iter.next();
			if (!matches(requestedWildcards, scope)) {
				iter.remove();
			}
		}

		return result;
	}
	/*
	 * Copied this methods from org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationRequestManager
	 */
	private Set<Pattern> constructWildcards(Set<String> scopes) {
		return UaaStringUtils.constructWildcards(scopes);
	}
	/*
	 * Copied this methods from org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationRequestManager
	 */
	private boolean matches(Set<Pattern> wildcards, String scope) {
		return UaaStringUtils.matches(wildcards, scope);
	}

	/*
	 * ********************************************************
	 *  This method could be removed if
	 *  spring-security-saml2-core would support the SAML2
	 *  validation from an Assertion and not only from a
	 *  SAMLResponse message
	 * ********************************************************
	 */
	// TODO Add Assertion Authentication into spring-security-saml2-core
	/*
	 * This method is a small wrapper for SAML2 Response.
	 * It only copies the data from an assertion into the required field, e.g. issuer
	 */
	private Response wrapAssertionIntoResponse(Assertion assertion, String assertionIssuer) {
		Response response = new ResponseBuilder().buildObject();
		Issuer issuer = new IssuerBuilder().buildObject();
		issuer.setValue(assertionIssuer);
		response.setIssuer(issuer);
		response.setID("id-" + System.currentTimeMillis());
		Status stat = new StatusBuilder().buildObject();
		// Set the status code
		StatusCode statCode = new StatusCodeBuilder().buildObject();
		statCode.setValue("urn:oasis:names:tc:SAML:2.0:status:Success");
		stat.setStatusCode(statCode);
		// Set the status Message
		StatusMessage statMesssage = new StatusMessageBuilder().buildObject();
		statMesssage.setMessage(null);
		stat.setStatusMessage(statMesssage);
		response.setStatus(stat);
		response.setVersion(SAMLVersion.VERSION_20);
		response.setIssueInstant(new DateTime());
		response.getAssertions().add(assertion);
		return response;
	}


}