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

import org.apache.velocity.app.VelocityEngine;
import org.opensaml.common.binding.security.SAMLProtocolMessageXMLSignatureSecurityPolicyRule;
import org.opensaml.saml2.binding.security.SAML2HTTPPostSimpleSignRule;
import org.opensaml.ws.message.decoder.MessageDecoder;
import org.opensaml.ws.message.encoder.MessageEncoder;
import org.opensaml.ws.security.SecurityPolicyRule;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.OutTransport;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HTTPTransport;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.processor.SAMLBindingImpl;

import java.util.List;

/**
 * Created by fhanik on 12/21/16.
 */
public class SamlAssertionBinding extends SAMLBindingImpl {

    /**
     * Pool for message deserializers.
     */
    protected ParserPool parserPool;

    /**
     * Creates default implementation of the binding.
     *
     * @param parserPool     parserPool for message deserialization
     */
    public SamlAssertionBinding(ParserPool parserPool, VelocityEngine engine) {
        this(parserPool, new SamlAssertionDecoder(parserPool), null);
    }

    /**
     * Implementation of the binding with custom encoder and decoder.
     *
     * @param parserPool     parserPool for message deserialization
     * @param decoder custom decoder implementation
     * @param encoder custom encoder implementation
     */
    public SamlAssertionBinding(ParserPool parserPool, MessageDecoder decoder, MessageEncoder encoder) {
        super(decoder, encoder);
        this.parserPool = parserPool;
    }

    public boolean supports(InTransport transport) {
        if (transport instanceof HTTPInTransport) {
            HTTPTransport t = (HTTPTransport) transport;
            return "POST".equalsIgnoreCase(t.getHTTPMethod()) && t.getParameterValue("assertion") != null;
        } else {
            return false;
        }
    }

    public boolean supports(OutTransport transport) {
        return transport instanceof HTTPOutTransport;
    }

    public String getBindingURI() {
        return "urn:oasis:names:tc:SAML:2.0:bindings:URI";
    }

    @Override
    public void getSecurityPolicy(List<SecurityPolicyRule> securityPolicy, SAMLMessageContext samlContext) {

        SignatureTrustEngine engine = samlContext.getLocalTrustEngine();
        securityPolicy.add(new SAML2HTTPPostSimpleSignRule(engine, parserPool, engine.getKeyInfoResolver()));
        securityPolicy.add(new SAMLProtocolMessageXMLSignatureSecurityPolicyRule(engine));

    }
}
