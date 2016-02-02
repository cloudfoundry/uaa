package org.cloudfoundry.identity.uaa.provider.saml.idp;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.context.SAMLMessageContext;

/**
 * Use this class in conjuction with
 * org.springframework.security.saml.SAMLProcessingFilter to ensure that when
 * SAMLProcessingFilter processes a SAML Authentication Request and builds a
 * SAMLMessageContext it identifies the peer entity as a SAML SP.
 */
public class IdpSamlContextProviderImpl extends SAMLContextProviderImpl {

    @Override
    public SAMLMessageContext getLocalEntity(HttpServletRequest request, HttpServletResponse response)
            throws MetadataProviderException {
        SAMLMessageContext context = super.getLocalEntity(request, response);
        context.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        return context;
    }
}
