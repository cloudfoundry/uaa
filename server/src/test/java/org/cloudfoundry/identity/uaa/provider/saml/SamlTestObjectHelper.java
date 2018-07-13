/*
 *  ****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 *  ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider.saml;


import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import org.joda.time.DateTime;
import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.provider.config.LocalProviderConfiguration;
import org.springframework.security.saml.provider.identity.config.LocalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.service.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AudienceRestriction;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.AuthenticationStatement;
import org.springframework.security.saml.saml2.authentication.Conditions;
import org.springframework.security.saml.saml2.authentication.Issuer;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.LogoutResponse;
import org.springframework.security.saml.saml2.authentication.NameIdPolicy;
import org.springframework.security.saml.saml2.authentication.NameIdPrincipal;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.authentication.Status;
import org.springframework.security.saml.saml2.authentication.StatusCode;
import org.springframework.security.saml.saml2.authentication.Subject;
import org.springframework.security.saml.saml2.authentication.SubjectConfirmation;
import org.springframework.security.saml.saml2.authentication.SubjectConfirmationData;
import org.springframework.security.saml.saml2.authentication.SubjectConfirmationMethod;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProvider;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProvider;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import static java.util.Arrays.asList;
import static org.springframework.security.saml.saml2.metadata.Binding.POST;
import static org.springframework.security.saml.saml2.metadata.Binding.REDIRECT;
import static org.springframework.security.saml.saml2.signature.AlgorithmMethod.RSA_SHA1;
import static org.springframework.security.saml.saml2.signature.DigestMethod.SHA1;
import static org.springframework.util.StringUtils.hasText;

public class SamlTestObjectHelper {
	public AlgorithmMethod DEFAULT_SIGN_ALGORITHM = RSA_SHA1;
	public DigestMethod DEFAULT_SIGN_DIGEST = SHA1;
	public long NOT_BEFORE = 60000;
	public long NOT_AFTER = 120000;
	public long SESSION_NOT_AFTER = 30 * 60 * 1000;

	private Clock time;

	public SamlTestObjectHelper(Clock time) {
		this.time = time;
	}

	public Clock getTime() {
		return time;
	}

	public SamlTestObjectHelper setTime(Clock time) {
		this.time = time;
		return this;
	}

	public ServiceProviderMetadata serviceProviderMetadata(String baseUrl,
                                                           LocalServiceProviderConfiguration configuration) {
		List<SimpleKey> keys = new LinkedList<>();
		keys.add(configuration.getKeys().getActive());
		keys.addAll(configuration.getKeys().getStandBy());
		SimpleKey signingKey = configuration.isSignMetadata() ? configuration.getKeys().getActive() : null;

		String aliasPath = getAliasPath(configuration);
		String prefix = hasText(configuration.getPrefix()) ? configuration.getPrefix() : "saml/sp/";

		ServiceProviderMetadata metadata =
			serviceProviderMetadata(
				baseUrl,
				signingKey,
				keys,
				prefix,
				aliasPath,
				configuration.getDefaultSigningAlgorithm(),
				configuration.getDefaultDigest()
			);

		if (!configuration.getNameIds().isEmpty()) {
			metadata.getServiceProvider().setNameIds(configuration.getNameIds());
		}

		return metadata;
	}

	protected String getAliasPath(LocalProviderConfiguration configuration) {
		try {
			return hasText(configuration.getAlias()) ?
				UriUtils.encode(configuration.getAlias(), StandardCharsets.ISO_8859_1.name()) :
				UriUtils.encode(configuration.getEntityId(), StandardCharsets.ISO_8859_1.name());
		} catch (UnsupportedEncodingException e) {
			throw new SamlException(e);
		}
	}

	public ServiceProviderMetadata serviceProviderMetadata(String baseUrl,
                                                           SimpleKey signingKey,
                                                           List<SimpleKey> keys,
                                                           String prefix,
                                                           String aliasPath,
                                                           AlgorithmMethod algorithmMethod,
                                                           DigestMethod digestMethod) {

		return new ServiceProviderMetadata()
			.setEntityId(baseUrl)
			.setId(UUID.randomUUID().toString())
			.setSigningKey(
				signingKey,
				algorithmMethod == null ? DEFAULT_SIGN_ALGORITHM : algorithmMethod,
				digestMethod == null ? DEFAULT_SIGN_DIGEST : digestMethod
			)
			.setProviders(
				asList(
					new ServiceProvider()
						.setKeys(keys)
						.setWantAssertionsSigned(true)
						.setAuthnRequestsSigned(signingKey != null)
						.setAssertionConsumerService(
							asList(
								getEndpoint(baseUrl, prefix + "SSO/alias/" + aliasPath, Binding.POST, 0, true),
								getEndpoint(baseUrl, prefix + "SSO/alias/" + aliasPath, REDIRECT, 1, false)
							)
						)
						.setNameIds(asList(NameId.PERSISTENT, NameId.EMAIL))
						.setKeys(keys)
						.setSingleLogoutService(
							asList(
								getEndpoint(baseUrl, prefix + "logout/alias/" + aliasPath, REDIRECT, 0, true)
							)
						)
				)
			);
	}

	public Endpoint getEndpoint(String baseUrl, String path, Binding binding, int index, boolean isDefault) {
		UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(baseUrl);
		builder.pathSegment(path);
		return getEndpoint(builder.build().toUriString(), binding, index, isDefault);
	}

	public Endpoint getEndpoint(String url, Binding binding, int index, boolean isDefault) {
		return
			new Endpoint()
				.setIndex(index)
				.setBinding(binding)
				.setLocation(url)
				.setDefault(isDefault)
				.setIndex(index);
	}

	public IdentityProviderMetadata identityProviderMetadata(String baseUrl,
                                                             LocalIdentityProviderConfiguration configuration) {
		List<SimpleKey> keys = new LinkedList<>();
		keys.add(configuration.getKeys().getActive());
		keys.addAll(configuration.getKeys().getStandBy());
		SimpleKey signingKey = configuration.isSignMetadata() ? configuration.getKeys().getActive() : null;

		String prefix = hasText(configuration.getPrefix()) ? configuration.getPrefix() : "saml/idp/";
		String aliasPath = getAliasPath(configuration);
		IdentityProviderMetadata metadata = identityProviderMetadata(
			baseUrl,
			signingKey,
			keys,
			prefix,
			aliasPath,
			configuration.getDefaultSigningAlgorithm(),
			configuration.getDefaultDigest()
		);
		if (!configuration.getNameIds().isEmpty()) {
			metadata.getIdentityProvider().setNameIds(configuration.getNameIds());
		}
		return metadata;
	}

	public IdentityProviderMetadata identityProviderMetadata(String baseUrl,
                                                             SimpleKey signingKey,
                                                             List<SimpleKey> keys,
                                                             String prefix,
                                                             String aliasPath,
                                                             AlgorithmMethod algorithmMethod,
                                                             DigestMethod digestMethod) {

		return new IdentityProviderMetadata()
			.setEntityId(baseUrl)
			.setId(UUID.randomUUID().toString())
			.setSigningKey(
				signingKey,
				algorithmMethod == null ? DEFAULT_SIGN_ALGORITHM : algorithmMethod,
				digestMethod == null ? DEFAULT_SIGN_DIGEST : digestMethod
			)
			.setProviders(
				asList(
					new IdentityProvider()
						.setWantAuthnRequestsSigned(true)
						.setSingleSignOnService(
							asList(
								getEndpoint(baseUrl, prefix + "SSO/alias/" + aliasPath, Binding.POST, 0, true),
								getEndpoint(baseUrl, prefix + "SSO/alias/" + aliasPath, REDIRECT, 1, false)
							)
						)
						.setNameIds(asList(NameId.PERSISTENT, NameId.EMAIL))
						.setKeys(keys)
						.setSingleLogoutService(
							asList(
								getEndpoint(baseUrl, prefix + "logout/alias/" + aliasPath, REDIRECT, 0, true)
							)
						)
				)
			);

	}

	public AuthenticationRequest authenticationRequest(ServiceProviderMetadata sp, IdentityProviderMetadata idp) {

		AuthenticationRequest request = new AuthenticationRequest()
			.setId(UUID.randomUUID().toString())
			.setIssueInstant(new DateTime(time.millis()))
			.setForceAuth(Boolean.FALSE)
			.setPassive(Boolean.FALSE)
			.setBinding(Binding.POST)
			.setAssertionConsumerService(getACSFromSp(sp))
			.setIssuer(new Issuer().setValue(sp.getEntityId()))
			.setDestination(idp.getIdentityProvider().getSingleSignOnService().get(0));
		if (sp.getServiceProvider().isAuthnRequestsSigned()) {
			request.setSigningKey(sp.getSigningKey(), sp.getAlgorithm(), sp.getDigest());
		}
		NameIdPolicy policy;
		if (idp.getDefaultNameId() != null) {
			policy = new NameIdPolicy(
				idp.getDefaultNameId(),
				sp.getEntityAlias(),
				true
			);
		}
		else {
			policy = new NameIdPolicy(
				idp.getIdentityProvider().getNameIds().get(0),
				sp.getEntityAlias(),
				true
			);
		}
		request.setNameIdPolicy(policy);
		return request;
	}

	private Endpoint getACSFromSp(ServiceProviderMetadata sp) {
		Endpoint endpoint = sp.getServiceProvider().getAssertionConsumerService().get(0);
		for (Endpoint e : sp.getServiceProvider().getAssertionConsumerService()) {
			if (e.isDefault()) {
				endpoint = e;
			}
		}
		return endpoint;
	}

	public Assertion assertion(ServiceProviderMetadata sp,
                               IdentityProviderMetadata idp,
                               AuthenticationRequest request,
                               String principal,
                               NameId principalFormat) {

		long now = time.millis();
		return new Assertion()
			.setSigningKey(idp.getSigningKey(), idp.getAlgorithm(), idp.getDigest())
			.setVersion("2.0")
			.setIssueInstant(new DateTime(now))
			.setId(UUID.randomUUID().toString())
			.setIssuer(idp.getEntityId())
			.setSubject(
				new Subject()
					.setPrincipal(
						new NameIdPrincipal()
							.setValue(principal)
							.setFormat(principalFormat)
							.setNameQualifier(sp.getEntityAlias())
							.setSpNameQualifier(sp.getEntityId())
					)
					.addConfirmation(
						new SubjectConfirmation()
							.setMethod(SubjectConfirmationMethod.BEARER)
							.setConfirmationData(
								new SubjectConfirmationData()
									.setInResponseTo(request != null ? request.getId() : null)
									//we don't set NotBefore. Gets rejected.
									//.setNotBefore(new DateTime(now - NOT_BEFORE))
									.setNotOnOrAfter(new DateTime(now + NOT_AFTER))
									.setRecipient(
										request != null ?
											request.getAssertionConsumerService().getLocation() :
											getACSFromSp(sp).getLocation()
									)
							)
					)


			)
			.setConditions(
				new Conditions()
					.setNotBefore(new DateTime(now - NOT_BEFORE))
					.setNotOnOrAfter(new DateTime(now + NOT_AFTER))
					.addCriteria(
						new AudienceRestriction()
							.addAudience(sp.getEntityId())

					)
			)
			.addAuthenticationStatement(
				new AuthenticationStatement()
					.setAuthInstant(new DateTime(now))
					.setSessionIndex(UUID.randomUUID().toString())
					.setSessionNotOnOrAfter(new DateTime(now + SESSION_NOT_AFTER))

			);

	}

	public Response response(AuthenticationRequest authn,
                             Assertion assertion,
                             ServiceProviderMetadata recipient,
                             IdentityProviderMetadata local) {
		Response result = new Response()
			.setAssertions(asList(assertion))
			.setId(UUID.randomUUID().toString())
			.setInResponseTo(authn != null ? authn.getId() : null)
			.setStatus(new Status().setCode(StatusCode.UNKNOWN_STATUS))
			.setIssuer(new Issuer().setValue(local.getEntityId()))
			.setSigningKey(local.getSigningKey(), local.getAlgorithm(), local.getDigest())
			.setIssueInstant(new DateTime())
			.setStatus(new Status().setCode(StatusCode.SUCCESS))
			.setVersion("2.0");
		Endpoint acs = (authn != null ? authn.getAssertionConsumerService() : null);
		if (acs == null) {
			acs = getPreferredACS(recipient.getServiceProvider().getAssertionConsumerService(), asList(POST));
		}
		if (acs != null) {
			result.setDestination(acs.getLocation());
		}
		return result;
	}

	public Endpoint getPreferredACS(List<Endpoint> eps,
                                    List<Binding> preferred) {
		if (eps == null || eps.isEmpty()) {
			return null;
		}
		Endpoint result = null;
		for (Endpoint e : eps) {
			if (e.isDefault() && preferred.contains(e.getBinding())) {
				result = e;
				break;
			}
		}
		for (Endpoint e : (result == null ? eps : Collections.<Endpoint>emptyList())) {
			if (e.isDefault()) {
				result = e;
				break;
			}
		}
		for (Endpoint e : (result == null ? eps : Collections.<Endpoint>emptyList())) {
			if (preferred.contains(e.getBinding())) {
				result = e;
				break;
			}
		}
		if (result == null) {
			result = eps.get(0);
		}
		return result;
	}

	public LogoutRequest logoutRequest(Metadata<? extends Metadata> recipient,
                                       Metadata<? extends Metadata> local,
                                       NameIdPrincipal principal) {


		LogoutRequest result = new LogoutRequest()
			.setId(UUID.randomUUID().toString())
			.setDestination(getSingleLogout(recipient.getSsoProviders().get(0).getSingleLogoutService()))
			.setIssuer(new Issuer().setValue(local.getEntityId()))
			.setIssueInstant(DateTime.now())
			.setNameId(principal)
			.setSigningKey(local.getSigningKey(), local.getAlgorithm(), local.getDigest());

		return result;
	}

	public Endpoint getSingleLogout(List<Endpoint> logoutService) {
		if (logoutService == null || logoutService.isEmpty()) {
			return null;
		}
		List<Endpoint> eps = logoutService;
		Endpoint result = null;
		for (Endpoint e : eps) {
			if (e.isDefault()) {
				result = e;
				break;
			}
			else if (REDIRECT.equals(e.getBinding())) {
				result = e;
				break;
			}
		}
		if (result == null) {
			result = eps.get(0);
		}
		return result;
	}

	public LogoutResponse logoutResponse(LogoutRequest request,
                                         IdentityProviderMetadata recipient,
                                         ServiceProviderMetadata local) {
		return logoutResponse(
			request,
			recipient,
			local,
			getSingleLogout(recipient.getIdentityProvider().getSingleLogoutService())
		);
	}

	public LogoutResponse logoutResponse(LogoutRequest request,
                                         Metadata<? extends Metadata> recipient,
                                         Metadata<? extends Metadata> local,
                                         Endpoint destination) {

		return new LogoutResponse()
			.setId(UUID.randomUUID().toString())
			.setInResponseTo(request != null ? request.getId() : null)
			.setDestination(destination != null ? destination.getLocation() : null)
			.setStatus(new Status().setCode(StatusCode.SUCCESS))
			.setIssuer(new Issuer().setValue(local.getEntityId()))
			.setSigningKey(local.getSigningKey(), local.getAlgorithm(), local.getDigest())
			.setIssueInstant(new DateTime())
			.setVersion("2.0");
	}

	public LogoutResponse logoutResponse(LogoutRequest request,
                                         ServiceProviderMetadata recipient,
                                         IdentityProviderMetadata local) {
		return logoutResponse(
			request,
			recipient,
			local,
			getSingleLogout(recipient.getServiceProvider().getSingleLogoutService())
		);
	}
}
