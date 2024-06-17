package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.impl.ResponseUnmarshaller;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

/**
 * SAML Authentication Provider responsible for validating of received SAML messages and creating authentication tokens.
 * <p>
 * Replace with {@link OpenSaml4AuthenticationProvider} when upgrading to OpenSAML 4.1+
 */
@Slf4j
@Value
public class SamlLoginAuthenticationProvider implements AuthenticationProvider, AuthenticationManager {

    private static final ParserPool parserPool;
    private static final ResponseUnmarshaller responseUnmarshaller;
    private final SamlUaaResponseAuthenticationConverter responseAuthenticationConverter;

    static {
        XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);

        responseUnmarshaller = (ResponseUnmarshaller) registry.getUnmarshallerFactory()
                .getUnmarshaller(Response.DEFAULT_ELEMENT_NAME);

        parserPool = registry.getParserPool();
    }

    public SamlLoginAuthenticationProvider(SamlUaaResponseAuthenticationConverter samlResponseAuthenticationConverter) {
        this.responseAuthenticationConverter = samlResponseAuthenticationConverter;
    }

    private static Saml2AuthenticationException createAuthenticationException(String code, String message,
                                                                              Exception cause) {
        return new Saml2AuthenticationException(new Saml2Error(code, message), cause);
    }

    /**
     * Attempts to authenticate the passed {@link Authentication} object, returning a
     * fully populated <code>UaaAuthentication</code> object (including granted authorities)
     * if successful.
     * <p>
     *
     * @see OpenSaml4AuthenticationProvider
     * https://docs.spring.io/spring-security/reference/5.8/migration/servlet/saml2.html#_use_opensaml_4
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        if (!supports(authentication.getClass())) {
            throw new IllegalArgumentException("Only Saml2AuthenticationToken is supported, " + authentication.getClass() + " was attempted");
        }

        Saml2AuthenticationToken authenticationToken = (Saml2AuthenticationToken) authentication;
        String serializedResponse = authenticationToken.getSaml2Response();
        Response response = parseResponse(serializedResponse);

        OpenSaml4AuthenticationProvider.ResponseToken responseToken = new OpenSaml4AuthenticationProvider.ResponseToken(response, authenticationToken);
        return responseAuthenticationConverter.convert(responseToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(Saml2AuthenticationToken.class);
    }

    private Response parseResponse(String response) throws Saml2Exception, Saml2AuthenticationException {
        try {
            Document document = parserPool.parse(new ByteArrayInputStream(response.getBytes(StandardCharsets.UTF_8)));
            Element element = document.getDocumentElement();
            return (Response) responseUnmarshaller.unmarshall(element);
        } catch (Exception ex) {
            throw createAuthenticationException(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA, ex.getMessage(), ex);
        }
    }
}
