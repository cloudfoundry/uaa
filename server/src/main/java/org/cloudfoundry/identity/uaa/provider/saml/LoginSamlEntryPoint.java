package org.cloudfoundry.identity.uaa.provider.saml;


import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.opensaml.common.SAMLException;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.websso.WebSSOProfileOptions;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class LoginSamlEntryPoint extends SAMLEntryPoint {


    private SamlIdentityProviderConfigurator providerDefinitionList;

    public SamlIdentityProviderConfigurator getProviderDefinitionList() {
        return providerDefinitionList;
    }

    public void setProviderDefinitionList(SamlIdentityProviderConfigurator providerDefinitionList) {
        this.providerDefinitionList = providerDefinitionList;
    }

    public WebSSOProfileOptions getDefaultProfileOptions() {
        return defaultOptions;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
        try {

            SAMLMessageContext context = contextProvider.getLocalAndPeerEntity(request, response);

            if (isECP(context)) {
                initializeECP(context, e);
            } else if (isDiscovery(context)) {
                initializeDiscovery(context);
            } else {
                initializeSSO(context, e);
            }
        } catch (SamlBindingNotSupportedException e1) {
            request.setAttribute("error_message_code", "error.sso.supported.binding");
            response.setStatus(400);
            request.getRequestDispatcher("/saml_error").include(request, response);
        } catch (SAMLException | MessageEncodingException | MetadataProviderException e1) {
            logger.debug("Error initializing entry point", e1);
            throw new ServletException(e1);
        }
    }

    @Override
    protected WebSSOProfileOptions getProfileOptions(SAMLMessageContext context, AuthenticationException exception) throws MetadataProviderException {
        WebSSOProfileOptions options = super.getProfileOptions(context, exception);
        String idpEntityId = context.getPeerEntityId();
        if (idpEntityId!=null) {
            ExtendedMetadata extendedMetadata = this.metadata.getExtendedMetadata(idpEntityId);
            if (extendedMetadata!=null) {
                String alias = extendedMetadata.getAlias();
                SamlIdentityProviderDefinition def = getIDPDefinition(alias);
                if (def.getNameID()!=null) {
                    options.setNameID(def.getNameID());
                }
                if (def.getAssertionConsumerIndex()>=0) {
                    options.setAssertionConsumerIndex(def.getAssertionConsumerIndex());
                }

                if (def.getAuthnContext() != null) {
                    options.setAuthnContexts(def.getAuthnContext());
                }
            }
        }
        return options;
    }

    private SamlIdentityProviderDefinition getIDPDefinition(String alias) throws MetadataProviderException {
        if (alias!=null) {
            for (SamlIdentityProviderDefinition def : getProviderDefinitionList().getIdentityProviderDefinitions()) {
                if (alias.equals(def.getIdpEntityAlias()) && IdentityZoneHolder.get().getId().equals(def.getZoneId())) {
                    return def;
                }
            }
        }
        throw new MetadataProviderNotFoundException("Unable to find SAML provider for alias:"+alias);
    }
}
