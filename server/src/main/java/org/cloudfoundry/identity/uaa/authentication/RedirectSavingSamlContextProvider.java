package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.flywaydb.core.internal.util.StringUtils;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLMessageContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

public class RedirectSavingSamlContextProvider implements SAMLContextProvider {

    private final SAMLContextProvider contextProviderDelegate;

    public RedirectSavingSamlContextProvider(SAMLContextProvider contextProviderDelegate) {
        this.contextProviderDelegate = contextProviderDelegate;
    }

    @Override
    public SAMLMessageContext getLocalEntity(HttpServletRequest request, HttpServletResponse response) throws MetadataProviderException {
        SAMLMessageContext context = contextProviderDelegate.getLocalEntity(request, response);
        return setRelayState(request, context);
    }

    @Override
    public SAMLMessageContext getLocalAndPeerEntity(HttpServletRequest request, HttpServletResponse response) throws MetadataProviderException {
        SAMLMessageContext context = contextProviderDelegate.getLocalAndPeerEntity(request, response);
        return setRelayState(request, context);
    }

    private static SAMLMessageContext setRelayState(HttpServletRequest request, SAMLMessageContext context) {
        Map<String, String> params = new HashMap<>();

        String redirectUri = request.getParameter("redirect");
        if(StringUtils.hasText(redirectUri)) { params.put("redirect", redirectUri); }

        String clientId = request.getParameter("client_id");
        if(StringUtils.hasText(clientId)) { params.put("client_id", clientId); }

        context.setRelayState(JsonUtils.writeValueAsString(params));
        return context;
    }
}
