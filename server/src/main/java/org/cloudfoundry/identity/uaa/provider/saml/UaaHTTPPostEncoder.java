package org.cloudfoundry.identity.uaa.provider.saml;

import org.apache.velocity.app.VelocityEngine;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UaaHTTPPostEncoder extends HTTPPostEncoder {

    private ZoneAwareSamlSecurityConfiguration zoneAwareSamlSecurityConfiguration;
    private static final Logger logger = LoggerFactory.getLogger(UaaHTTPPostEncoder.class);

    public UaaHTTPPostEncoder(VelocityEngine velocityEngine, ZoneAwareSamlSecurityConfiguration securityConfiguration) {
        super(velocityEngine, "/templates/saml2-post-binding.vm");
        this.zoneAwareSamlSecurityConfiguration = securityConfiguration;
    }

    @Override
    protected void signMessage(SAMLMessageContext messageContext) throws MessageEncodingException {
        SAMLObject outboundSAML = messageContext.getOutboundSAMLMessage();
        Credential signingCredential = messageContext.getOuboundSAMLMessageSigningCredential();

        if (outboundSAML instanceof SignableSAMLObject && signingCredential != null) {
            SignableSAMLObject signableMessage = (SignableSAMLObject) outboundSAML;

            XMLObjectBuilder<Signature> signatureBuilder = Configuration.getBuilderFactory().getBuilder(
                    Signature.DEFAULT_ELEMENT_NAME);
            Signature signature = signatureBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);

            signature.setSigningCredential(signingCredential);
            try {
                SecurityHelper.prepareSignatureParams(signature, signingCredential, zoneAwareSamlSecurityConfiguration, null);
            } catch (SecurityException e) {
                throw new MessageEncodingException("Error preparing signature for signing", e);
            }

            signableMessage.setSignature(signature);

            try {
                Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(signableMessage);
                if (marshaller == null) {
                    throw new MessageEncodingException("No marshaller registered for "
                            + signableMessage.getElementQName() + ", unable to marshall in preperation for signing");
                }
                marshaller.marshall(signableMessage);

                Signer.signObject(signature);
            } catch (MarshallingException e) {
                logger.error("Unable to marshall protocol message in preparation for signing", e);
                throw new MessageEncodingException("Unable to marshall protocol message in preparation for signing", e);
            } catch (SignatureException e) {
                logger.error("Unable to sign protocol message", e);
                throw new MessageEncodingException("Unable to sign protocol message", e);
            }
        }
    }
}