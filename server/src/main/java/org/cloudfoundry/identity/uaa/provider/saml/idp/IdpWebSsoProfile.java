package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.opensaml.common.SAMLException;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.context.SAMLMessageContext;

/**
 * Interface for sending a SAML Response to SAML Service Provider during Web Single Sign-On profile.
 */
public interface IdpWebSsoProfile {

  void sendResponse(
      Authentication authentication, SAMLMessageContext context, IdpWebSSOProfileOptions options)
      throws SAMLException, MetadataProviderException, MessageEncodingException, SecurityException,
          MarshallingException, SignatureException;

  AuthnRequest buildIdpInitiatedAuthnRequest(
      String nameIDFormat, String spEntityID, String assertionUrl);
}
