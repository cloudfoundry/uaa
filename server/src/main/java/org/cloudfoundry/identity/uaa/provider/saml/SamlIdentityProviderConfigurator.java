package org.cloudfoundry.identity.uaa.provider.saml;

import org.apache.commons.io.IOUtils;
import org.apache.hc.core5.net.URIBuilder;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.IdpAlreadyExistsException;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.springframework.util.StringUtils.hasText;

@Component("metaDataProviders")
public class SamlIdentityProviderConfigurator {
    private final IdentityProviderProvisioning providerProvisioning;
    private final IdentityZoneManager identityZoneManager;
    private final FixedHttpMetaDataProvider fixedHttpMetaDataProvider;

    public SamlIdentityProviderConfigurator(
            final @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning providerProvisioning,
            final @Qualifier("identityZoneManager") IdentityZoneManager identityZoneManager,
            final @Qualifier("fixedHttpMetaDataProvider") FixedHttpMetaDataProvider fixedHttpMetaDataProvider) {
        this.providerProvisioning = providerProvisioning;
        this.identityZoneManager = identityZoneManager;
        this.fixedHttpMetaDataProvider = fixedHttpMetaDataProvider;
    }

    public List<SamlIdentityProviderDefinition> getIdentityProviderDefinitions() {
        return getIdentityProviderDefinitionsForZone(identityZoneManager.getCurrentIdentityZone());
    }

    public AbstractIdentityProviderDefinition getIdentityProviderDefinitionsForOrigin(IdentityZone zone, String origin) {
        try {
            return providerProvisioning.retrieveByOrigin(origin, zone.getId()).getConfig();
        } catch (EmptyResultDataAccessException e) {
            return null;
        }
    }

    public AbstractIdentityProviderDefinition getIdentityProviderDefinitionsForIssuer(IdentityZone zone, String issuer) {
        try {
            return providerProvisioning.retrieveByExternId(issuer, OriginKeys.SAML, zone.getId()).getConfig();
        } catch (EmptyResultDataAccessException e) {
            return null;
        }
    }

    public List<SamlIdentityProviderDefinition> getIdentityProviderDefinitionsForZone(IdentityZone zone) {
        return providerProvisioning.retrieveActiveByTypes(zone.getId(), OriginKeys.SAML).stream()
                .map(samlIdp -> (SamlIdentityProviderDefinition) samlIdp.getConfig())
                .toList();
    }

    public List<SamlIdentityProviderDefinition> getIdentityProviderDefinitions(List<String> allowedIdps, IdentityZone zone) {
        return getIdentityProviderDefinitionsForZone(zone).stream()
                .filter(def -> allowedIdps == null || allowedIdps.contains(def.getIdpEntityAlias())).toList();
    }

    /**
     * adds or replaces a SAML identity proviider
     *
     * @param providerDefinition - the provider to be added
     * @param creation           - check new created config
     */
    public synchronized String validateSamlIdentityProviderDefinition(SamlIdentityProviderDefinition providerDefinition, boolean creation) {
        RelyingPartyRegistration added;
        if (providerDefinition == null) {
            throw new NullPointerException();
        }
        if (!hasText(providerDefinition.getIdpEntityAlias())) {
            throw new NullPointerException("SAML IDP Alias must be set");
        }
        if (!hasText(providerDefinition.getZoneId())) {
            throw new NullPointerException("IDP Zone Id must be set");
        }
        SamlIdentityProviderDefinition clone = providerDefinition.clone();
        added = getExtendedMetadataDelegate(clone);
        String entityIDToBeAdded = added.getAssertingPartyDetails().getEntityId();
        if (!hasText(entityIDToBeAdded)) {
            throw new IllegalStateException("Emtpy entityID for SAML provider with zoneId:" + providerDefinition.getZoneId() + " and origin:" + providerDefinition.getIdpEntityAlias());
        }

        boolean entityIDexists = creation && entityIdExists(entityIDToBeAdded, providerDefinition.getZoneId());

        if (!entityIDexists) {
            for (SamlIdentityProviderDefinition existing : getIdentityProviderDefinitions()) {
                if (existing.getType() != SamlIdentityProviderDefinition.MetadataLocation.DATA) {
                    continue;
                }
                RelyingPartyRegistration existingProvider = getExtendedMetadataDelegate(existing);
                if (entityIDToBeAdded.equals(existingProvider.getAssertingPartyDetails().getEntityId()) && !existing.getUniqueAlias().equals(clone.getUniqueAlias())) {
                    entityIDexists = true;
                    break;
                }
            }
        }

        if (entityIDexists) {
            throw new IdpAlreadyExistsException("Duplicate entity ID:" + entityIDToBeAdded);
        }
        return entityIDToBeAdded;
    }

    private boolean entityIdExists(String entityId, String zoneId) {
        try {
            return providerProvisioning.retrieveByExternId(entityId, OriginKeys.SAML, zoneId) != null;
        } catch (EmptyResultDataAccessException e) {
            return false;
        }
    }

    public RelyingPartyRegistration getExtendedMetadataDelegate(SamlIdentityProviderDefinition def) {
        return switch (def.getType()) {
            case DATA -> configureXMLMetadata(def);
            case URL -> configureURLMetadata(def);
            default ->
                throw new IllegalStateException("Invalid metadata type for alias[" + def.getIdpEntityAlias() + "]:" + def.getMetaDataLocation());
        };
    }

    protected RelyingPartyRegistration configureXMLMetadata(SamlIdentityProviderDefinition def) {
        return RelyingPartyRegistrations.fromMetadata(IOUtils.toInputStream(def.getMetaDataLocation(), StandardCharsets.UTF_8)).build();
    }

    protected String adjustURIForPort(String uri) throws URISyntaxException {
        URI metadataURI = new URI(uri);
        if (metadataURI.getPort() < 0) {
            return switch (metadataURI.getScheme()) {
                case "https" -> new URIBuilder(uri).setPort(443).build().toString();
                case "http" -> new URIBuilder(uri).setPort(80).build().toString();
                default -> uri;
            };
        }
        return uri;
    }

    protected RelyingPartyRegistration configureURLMetadata(SamlIdentityProviderDefinition def) {
        try {
            def = def.clone();
            String adjustedMetadataURIForPort = adjustURIForPort(def.getMetaDataLocation());
            byte[] metadata = fixedHttpMetaDataProvider.fetchMetadata(adjustedMetadataURIForPort, def.isSkipSslValidation());

            def.setMetaDataLocation(new String(metadata, StandardCharsets.UTF_8));
            return configureXMLMetadata(def);
        } catch (URISyntaxException e) {
            throw new IllegalStateException("Invalid socket factory(invalid URI):" + def.getMetaDataLocation(), e);
        }
    }
}
