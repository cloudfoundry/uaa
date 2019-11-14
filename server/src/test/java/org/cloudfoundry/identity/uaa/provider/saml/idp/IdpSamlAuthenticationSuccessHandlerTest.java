package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.SAMLException;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.MetadataManager;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class IdpSamlAuthenticationSuccessHandlerTest {

    private final SamlTestUtils samlTestUtils = new SamlTestUtils();

    @Before
    public void setup() throws ConfigurationException {
        samlTestUtils.initialize();
    }

    @Test
    public void testOnAuthenticationSuccess() throws ServletException, MetadataProviderException,
            MessageEncodingException, SAMLException, SecurityException, MarshallingException, SignatureException {
        IdpSamlAuthenticationSuccessHandler successHandler = new IdpSamlAuthenticationSuccessHandler();

        SAMLMessageContext context = samlTestUtils.mockSamlMessageContext();
        Authentication authentication = samlTestUtils.mockUaaAuthenticationWithSamlMessageContext(context);

        IdpExtendedMetadata idpExtendedMetaData = new IdpExtendedMetadata();
        idpExtendedMetaData.setAssertionsSigned(true);

        MetadataManager metadataManager = mock(MetadataManager.class);
        when(metadataManager.getExtendedMetadata(context.getLocalEntityId())).thenReturn(idpExtendedMetaData);
        when(metadataManager.getEntityDescriptor(context.getPeerEntityId()))
                .thenReturn(context.getPeerEntityMetadata());
        when(metadataManager.getRole(context.getPeerEntityId(), context.getPeerEntityRole(), SAMLConstants.SAML20P_NS))
                .thenReturn(context.getPeerEntityRoleMetadata());
        successHandler.setMetadataManager(metadataManager);

        IdpWebSsoProfile profile = mock(IdpWebSsoProfile.class);
        doNothing().when(profile).sendResponse(any(), any(), any());
        successHandler.setIdpWebSsoProfile(profile);

        HttpServletRequest request = new MockHttpServletRequest();
        HttpServletResponse response = new MockHttpServletResponse();
        successHandler.onAuthenticationSuccess(request, response, authentication);
    }

    @Test(expected = ServletException.class)
    public void testOnAuthenticationSuccessFailureIfIdpExtendedMetadataMissing()
            throws ServletException, MetadataProviderException {
        IdpSamlAuthenticationSuccessHandler successHandler = new IdpSamlAuthenticationSuccessHandler();

        SAMLMessageContext context = samlTestUtils.mockSamlMessageContext();
        Authentication authentication = samlTestUtils.mockUaaAuthenticationWithSamlMessageContext(context);

        MetadataManager metadataManager = mock(MetadataManager.class);
        when(metadataManager.getExtendedMetadata(context.getLocalEntityId()))
                .thenThrow(new MetadataProviderException());
        successHandler.setMetadataManager(metadataManager);

        HttpServletRequest request = new MockHttpServletRequest();
        HttpServletResponse response = new MockHttpServletResponse();
        successHandler.onAuthenticationSuccess(request, response, authentication);
    }

    @Test(expected = ServletException.class)
    public void testOnAuthenticationSuccessFailureIfIdpPeerEntityIdNull()
            throws ServletException, MetadataProviderException, MessageEncodingException, SAMLException,
            SecurityException, MarshallingException, SignatureException {
        IdpSamlAuthenticationSuccessHandler successHandler = new IdpSamlAuthenticationSuccessHandler();

        SAMLMessageContext context = samlTestUtils.mockSamlMessageContext();
        Authentication authentication = samlTestUtils.mockUaaAuthenticationWithSamlMessageContext(context);

        IdpExtendedMetadata idpExtendedMetaData = new IdpExtendedMetadata();
        idpExtendedMetaData.setAssertionsSigned(true);

        MetadataManager metadataManager = mock(MetadataManager.class);
        when(metadataManager.getExtendedMetadata(context.getLocalEntityId())).thenReturn(idpExtendedMetaData);
        when(metadataManager.getEntityDescriptor(context.getPeerEntityId()))
                .thenReturn(context.getPeerEntityMetadata());
        when(metadataManager.getRole(context.getPeerEntityId(), context.getPeerEntityRole(), SAMLConstants.SAML20P_NS))
                .thenReturn(context.getPeerEntityRoleMetadata());
        successHandler.setMetadataManager(metadataManager);

        IdpWebSsoProfile profile = mock(IdpWebSsoProfile.class);
        doNothing().when(profile).sendResponse(any(), any(), any());
        successHandler.setIdpWebSsoProfile(profile);

        context.setPeerEntityId(null);
        HttpServletRequest request = new MockHttpServletRequest();
        HttpServletResponse response = new MockHttpServletResponse();
        successHandler.onAuthenticationSuccess(request, response, authentication);
    }

    @Test(expected = ServletException.class)
    public void testOnAuthenticationSuccessFailureIfIdpPeerEntityMetadataNull()
            throws ServletException, MetadataProviderException, MessageEncodingException, SAMLException,
            SecurityException, MarshallingException, SignatureException {
        IdpSamlAuthenticationSuccessHandler successHandler = new IdpSamlAuthenticationSuccessHandler();

        SAMLMessageContext context = samlTestUtils.mockSamlMessageContext();
        Authentication authentication = samlTestUtils.mockUaaAuthenticationWithSamlMessageContext(context);

        IdpExtendedMetadata idpExtendedMetaData = new IdpExtendedMetadata();
        idpExtendedMetaData.setAssertionsSigned(true);

        MetadataManager metadataManager = mock(MetadataManager.class);
        when(metadataManager.getExtendedMetadata(context.getLocalEntityId())).thenReturn(idpExtendedMetaData);
        when(metadataManager.getEntityDescriptor(context.getPeerEntityId())).thenReturn(null);
        when(metadataManager.getRole(context.getPeerEntityId(), context.getPeerEntityRole(), SAMLConstants.SAML20P_NS))
                .thenReturn(context.getPeerEntityRoleMetadata());
        successHandler.setMetadataManager(metadataManager);

        IdpWebSsoProfile profile = mock(IdpWebSsoProfile.class);
        doNothing().when(profile).sendResponse(any(), any(), any());
        successHandler.setIdpWebSsoProfile(profile);

        HttpServletRequest request = new MockHttpServletRequest();
        HttpServletResponse response = new MockHttpServletResponse();
        successHandler.onAuthenticationSuccess(request, response, authentication);
    }

    @Test(expected = ServletException.class)
    public void testOnAuthenticationSuccessFailureIfIdpPeerRoleDescriptorNull()
            throws ServletException, MetadataProviderException, MessageEncodingException, SAMLException,
            SecurityException, MarshallingException, SignatureException {
        IdpSamlAuthenticationSuccessHandler successHandler = new IdpSamlAuthenticationSuccessHandler();

        SAMLMessageContext context = samlTestUtils.mockSamlMessageContext();
        Authentication authentication = samlTestUtils.mockUaaAuthenticationWithSamlMessageContext(context);

        IdpExtendedMetadata idpExtendedMetaData = new IdpExtendedMetadata();
        idpExtendedMetaData.setAssertionsSigned(true);

        MetadataManager metadataManager = mock(MetadataManager.class);
        when(metadataManager.getExtendedMetadata(context.getLocalEntityId())).thenReturn(idpExtendedMetaData);
        when(metadataManager.getEntityDescriptor(context.getPeerEntityId()))
                .thenReturn(context.getPeerEntityMetadata());
        when(metadataManager.getRole(context.getPeerEntityId(), context.getPeerEntityRole(), SAMLConstants.SAML20P_NS))
                .thenReturn(null);
        successHandler.setMetadataManager(metadataManager);

        IdpWebSsoProfile profile = mock(IdpWebSsoProfile.class);
        doNothing().when(profile).sendResponse(any(), any(), any());
        successHandler.setIdpWebSsoProfile(profile);

        HttpServletRequest request = new MockHttpServletRequest();
        HttpServletResponse response = new MockHttpServletResponse();
        successHandler.onAuthenticationSuccess(request, response, authentication);
    }
}
