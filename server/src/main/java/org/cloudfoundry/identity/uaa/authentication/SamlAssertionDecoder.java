/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.provider.saml.SamlRedirectUtils;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.binding.decoding.BaseSAML2MessageDecoder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Copy/paste from org.opensaml.saml2.binding.decoding.HTTPPostDecoder
 * with two minor changes
 * 1. base64 decoding is doing base64url decoding
 * 2. The unmarshalling of the object gets wrapped in a SamlResponse object
 */

public class SamlAssertionDecoder extends BaseSAML2MessageDecoder {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(SamlAssertionDecoder.class);

    /** Constructor. */
    public SamlAssertionDecoder() {
        super();
    }

    /**
     * Constructor.
     *
     * @param pool parser pool used to deserialize messages
     */
    public SamlAssertionDecoder(ParserPool pool) {
        super(pool);
    }

    /** {@inheritDoc} */
    public String getBindingURI() {
        return "urn:oasis:names:tc:SAML:2.0:bindings:URI";
    }

    /** {@inheritDoc} */
    protected boolean isIntendedDestinationEndpointURIRequired(SAMLMessageContext samlMsgCtx) {
        return isMessageSigned(samlMsgCtx);
    }

    /** {@inheritDoc} */
    protected void doDecode(MessageContext messageContext) throws MessageDecodingException {
        if (!(messageContext instanceof SAMLMessageContext)) {
            log.error("Invalid message context type, this decoder only support SAMLMessageContext");
            throw new MessageDecodingException(
                "Invalid message context type, this decoder only support SAMLMessageContext");
        }

        if (!(messageContext.getInboundMessageTransport() instanceof HTTPInTransport)) {
            log.error("Invalid inbound message transport type, this decoder only support HTTPInTransport");
            throw new MessageDecodingException(
                "Invalid inbound message transport type, this decoder only support HTTPInTransport");
        }

        SAMLMessageContext samlMsgCtx = (SAMLMessageContext) messageContext;

        HTTPInTransport inTransport = (HTTPInTransport) samlMsgCtx.getInboundMessageTransport();
        if (!inTransport.getHTTPMethod().equalsIgnoreCase("POST")) {
            throw new MessageDecodingException("This message decoder only supports the HTTP POST method");
        }

        String relayState = inTransport.getParameterValue("RelayState");
        samlMsgCtx.setRelayState(relayState);
        log.debug("Decoded SAML relay state of: {}", relayState);

        InputStream base64DecodedMessage = getBase64DecodedMessage(inTransport);
        Assertion inboundMessage = (Assertion) unmarshallMessage(base64DecodedMessage);
        Response response = SamlRedirectUtils.wrapAssertionIntoResponse(inboundMessage, inboundMessage.getIssuer().getValue());
        samlMsgCtx.setInboundMessage(response);
        samlMsgCtx.setInboundSAMLMessage(response);
        log.debug("Decoded SAML message");

        populateMessageContext(samlMsgCtx);
    }

    /**
     * Gets the Base64 encoded message from the request and decodes it.
     *
     * @param transport inbound message transport
     *
     * @return decoded message
     *
     * @throws MessageDecodingException thrown if the message does not contain a base64 encoded SAML message
     */
    protected InputStream getBase64DecodedMessage(HTTPInTransport transport) throws MessageDecodingException {
        log.debug("Getting Base64 encoded message from request");
        String encodedMessage = transport.getParameterValue("assertion");


        if (DatatypeHelper.isEmpty(encodedMessage)) {
            log.error("Request did not contain either a SAMLRequest or "
                          + "SAMLResponse parameter.  Invalid request for SAML 2 HTTP POST binding.");
            throw new MessageDecodingException("No SAML message present in request");
        }

        log.trace("Base64 decoding SAML message:\n{}", encodedMessage);
        byte[] decodedBytes = org.apache.commons.codec.binary.Base64.decodeBase64(encodedMessage.getBytes(StandardCharsets.UTF_8));
        if(decodedBytes == null){
            log.error("Unable to Base64 decode SAML message");
            throw new MessageDecodingException("Unable to Base64 decode SAML message");
        }

        log.trace("Decoded SAML message:\n{}", new String(decodedBytes));
        return new ByteArrayInputStream(decodedBytes);
    }
}
