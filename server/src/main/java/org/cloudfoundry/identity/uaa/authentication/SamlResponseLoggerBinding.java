package org.cloudfoundry.identity.uaa.authentication;

import org.opensaml.ws.message.decoder.MessageDecoder;
import org.opensaml.ws.message.encoder.MessageEncoder;
import org.opensaml.ws.security.SecurityPolicyRule;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.OutTransport;
import org.opensaml.ws.transport.http.HTTPTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.processor.SAMLBinding;

import java.util.List;

public class SamlResponseLoggerBinding implements SAMLBinding {

    private static final Logger LOGGER = LoggerFactory.getLogger(SamlResponseLoggerBinding.class);

    @Override
    public boolean supports(InTransport transport) {
        HTTPTransport t = (HTTPTransport) transport;
        LOGGER.warn("Malformed SAML response. More details at logger level DEBUG.");
        LOGGER.debug("POST");
        return false;
    }

    @Override
    public boolean supports(OutTransport transport) {
        return false;
    }

    @Override
    public MessageDecoder getMessageDecoder() {
        return null;
    }

    @Override
    public MessageEncoder getMessageEncoder() {
        return null;
    }

    @Override
    public String getBindingURI() {
        return null;
    }

    @Override
    public void getSecurityPolicy(List<SecurityPolicyRule> securityPolicy, SAMLMessageContext samlContext) {

    }
}
