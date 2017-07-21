package org.cloudfoundry.identity.uaa.provider.saml;


import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.websso.WebSSOProfileImpl;

public class SPWebSSOProfileImpl extends WebSSOProfileImpl {
    public SPWebSSOProfileImpl () {}

    public SPWebSSOProfileImpl(SAMLProcessor processor, MetadataManager manager) {
        super(processor, manager);
    }

    /**
     * Determines whether given SingleSignOn service can be used together with this profile. Bindings POST, Artifact
     * and Redirect are supported for WebSSO.
     *
     * @param endpoint endpoint
     * @return true if endpoint is supported
     * @throws MetadataProviderException in case system can't verify whether endpoint is supported or not
     */
    @Override
    protected boolean isEndpointSupported(SingleSignOnService endpoint) throws MetadataProviderException {
        return org.opensaml.common.xml.SAMLConstants.SAML2_POST_BINDING_URI.equals(endpoint.getBinding()) ||
                org.opensaml.common.xml.SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(endpoint.getBinding());
    }
}
