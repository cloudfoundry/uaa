/*
 * Copyright 2002-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Resolves the correct SamlIdp from request parameters when relyingPartyRegistrationId==null
 * Such as on SAML2 bearer and IdP initiated SSO
 * <p/>
 * Originally copied from Spring Security's DefaultRelyingPartyRegistrationResolver
 */
@Slf4j
public final class UaaRelyingPartyRegistrationResolver implements Converter<HttpServletRequest, RelyingPartyRegistration>, RelyingPartyRegistrationResolver {

    private final String uaaWideSamlEntityIDAlias;
    private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;
    private final RequestMatcher registrationRequestMatcher = new AntPathRequestMatcher("/**/{registrationId}");

    public UaaRelyingPartyRegistrationResolver(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository,
            String uaaWideSamlEntityIDAlias) {
        Assert.notNull(relyingPartyRegistrationRepository, "relyingPartyRegistrationRepository cannot be null");
        this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
        this.uaaWideSamlEntityIDAlias = uaaWideSamlEntityIDAlias;
    }

    public RelyingPartyRegistration convert(HttpServletRequest request) {
        return this.resolve(request, null);
    }

    @Override
    public RelyingPartyRegistration resolve(HttpServletRequest request, String relyingPartyRegistrationId) {

        if (relyingPartyRegistrationId == null) {
            if (log.isTraceEnabled()) {
                log.trace("Attempting to resolve from {} since registrationId is null", this.registrationRequestMatcher);
            }

            String resolvedEntityId = this.registrationRequestMatcher.matcher(request).getVariables().get("registrationId");
            String samlResponseParameter = request.getParameter("SAMLResponse");
            relyingPartyRegistrationId = resolveFromRequest(request, resolvedEntityId, samlResponseParameter);
        }

        if (relyingPartyRegistrationId == null) {
            if (log.isTraceEnabled()) {
                log.trace("Returning null registration since registrationId is null");
            }

            return null;
        } else {
            RelyingPartyRegistration relyingPartyRegistration = this.relyingPartyRegistrationRepository.findByRegistrationId(relyingPartyRegistrationId);
            if (relyingPartyRegistration == null) {
                return null;
            } else {
                String applicationUri = getApplicationUri(request);
                Function<String, String> templateResolver = this.templateResolver(applicationUri, relyingPartyRegistration);
                String relyingPartyEntityId = templateResolver.apply(relyingPartyRegistration.getEntityId());
                String assertionConsumerServiceLocation = templateResolver.apply(relyingPartyRegistration.getAssertionConsumerServiceLocation());
                String singleLogoutServiceLocation = templateResolver.apply(relyingPartyRegistration.getSingleLogoutServiceLocation());
                String singleLogoutServiceResponseLocation = templateResolver.apply(relyingPartyRegistration.getSingleLogoutServiceResponseLocation());
                return RelyingPartyRegistration.withRelyingPartyRegistration(relyingPartyRegistration).entityId(relyingPartyEntityId).assertionConsumerServiceLocation(assertionConsumerServiceLocation).singleLogoutServiceLocation(singleLogoutServiceLocation).singleLogoutServiceResponseLocation(singleLogoutServiceResponseLocation).build();
            }
        }
    }

    private String resolveFromRequest(HttpServletRequest request, String resolvedEntityId, String samlResponseParameter) {
        String relyingPartyRegistrationId = null;
        if (resolvedEntityId != null && resolvedEntityId.endsWith(uaaWideSamlEntityIDAlias) && samlResponseParameter != null) {
            if (log.isTraceEnabled()) {
                log.trace("Attempting to resolve from SAMLResponse parameter");
            }
            String assertionXml = null;
            if ("POST".equalsIgnoreCase(request.getMethod())) {
                assertionXml = new String(Saml2Utils.samlDecode(samlResponseParameter), StandardCharsets.UTF_8);
            } else if ("GET".equalsIgnoreCase(request.getMethod())) {
                assertionXml = Saml2Utils.samlDecodeAndInflate(samlResponseParameter);
            }
            if (assertionXml != null) {
                resolvedEntityId = Saml2BearerGrantAuthenticationConverter
                        .getIssuer(Saml2BearerGrantAuthenticationConverter.parseSamlResponse(assertionXml));
                relyingPartyRegistrationId = resolvedEntityId;
            }
        }
        return relyingPartyRegistrationId;
    }

    private Function<String, String> templateResolver(String applicationUri, RelyingPartyRegistration relyingParty) {
        return template -> resolveUrlTemplate(template, applicationUri, relyingParty);
    }

    private static String resolveUrlTemplate(String template, String baseUrl, RelyingPartyRegistration relyingParty) {
        if (template == null) {
            return null;
        } else {
            return UriComponentsBuilder.fromUriString(template).buildAndExpand(constructUriVariables(baseUrl, relyingParty)).toUriString();
        }
    }

    private static Map<String, String> constructUriVariables(String baseUrl, RelyingPartyRegistration relyingParty) {
        String entityId = relyingParty.getAssertingPartyDetails().getEntityId();
        String registrationId = relyingParty.getRegistrationId();
        Map<String, String> uriVariables = new HashMap<>();
        UriComponents uriComponents = UriComponentsBuilder.fromUriString(baseUrl).replaceQuery(null).fragment(null).build();
        String scheme = uriComponents.getScheme();
        uriVariables.put("baseScheme", scheme != null ? scheme : "");
        String host = uriComponents.getHost();
        uriVariables.put("baseHost", host != null ? host : "");
        int port = uriComponents.getPort();
        uriVariables.put("basePort", port == -1 ? "" : ":" + port);
        String path = uriComponents.getPath();
        if (StringUtils.hasLength(path) && path.charAt(0) != '/') {
            path = '/' + path;
        }

        uriVariables.put("basePath", path != null ? path : "");
        uriVariables.put("baseUrl", uriComponents.toUriString());
        uriVariables.put("entityId", StringUtils.hasText(entityId) ? entityId : "");
        uriVariables.put("registrationId", StringUtils.hasText(registrationId) ? registrationId : "");
        return uriVariables;
    }

    private static String getApplicationUri(HttpServletRequest request) {
        UriComponents uriComponents = UriComponentsBuilder.fromUriString(UrlUtils.buildFullRequestUrl(request)).replacePath(request.getContextPath()).replaceQuery(null).fragment(null).build();
        return uriComponents.toUriString();
    }
}