package org.cloudfoundry.identity.uaa.provider.saml;

import org.apache.commons.io.ByteOrderMark;
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
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
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
        } catch (EmptyResultDataAccessException _) {
            return null;
        }
    }

    public AbstractIdentityProviderDefinition getIdentityProviderDefinitionsForIssuer(IdentityZone zone, String issuer) {
        try {
            return providerProvisioning.retrieveByExternId(issuer, OriginKeys.SAML, zone.getId()).getConfig();
        } catch (EmptyResultDataAccessException _) {
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
        String entityIDToBeAdded = added.getAssertingPartyMetadata().getEntityId();
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
                if (entityIDToBeAdded.equals(existingProvider.getAssertingPartyMetadata().getEntityId()) && !existing.getUniqueAlias().equals(clone.getUniqueAlias())) {
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
        } catch (EmptyResultDataAccessException _) {
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
        SamlIdentityProviderDefinition resolved = def.clone();
        resolved.setMetaDataLocation(resolveMetadataXml(def));
        return configureXMLMetadata(resolved);
    }

    /**
     * Resolves a SAML IDP definition's metadata to its literal XML content. If the
     * definition's metadata is a URL, it is fetched via the {@code skipSslValidation}-aware
     * {@link FixedHttpMetaDataProvider} (the same trust/cache behavior used to validate an
     * IDP on creation); otherwise the already-inline XML is returned unchanged.
     */
    public String resolveMetadataXml(SamlIdentityProviderDefinition def) {
        String metadataLocation = def.getMetaDataLocation();
        if (!hasText(metadataLocation) || SamlIdentityProviderDefinition.getType(metadataLocation) != SamlIdentityProviderDefinition.MetadataLocation.URL) {
            return metadataLocation;
        }
        try {
            String adjustedMetadataURIForPort = adjustURIForPort(metadataLocation);
            byte[] metadata = fixedHttpMetaDataProvider.fetchMetadata(adjustedMetadataURIForPort, def.isSkipSslValidation(),
                    def.getCaCertificates(), def.getUniqueAlias());
            return new String(metadata, detectCharset(metadata));
        } catch (URISyntaxException e) {
            throw new IllegalStateException("Invalid socket factory(invalid URI):" + metadataLocation, e);
        }
    }

    /**
     * Detects the charset of fetched metadata bytes from a leading byte order marker. Only
     * UTF-16 needs to be sniffed explicitly here: a UTF-8 byte order marker, if present, already
     * decodes correctly under the UTF-8 default and is stripped later by
     * {@link SamlIdentityProviderDefinition#getType(String)}, since it decodes to the same
     * character (U+FEFF) as a correctly-decoded UTF-16 BOM.
     */
    static Charset detectCharset(byte[] metadata) {
        if (hasLeadingByteOrderMark(metadata, ByteOrderMark.UTF_16LE)) {
            return StandardCharsets.UTF_16LE;
        }
        if (hasLeadingByteOrderMark(metadata, ByteOrderMark.UTF_16BE)) {
            return StandardCharsets.UTF_16BE;
        }
        return StandardCharsets.UTF_8;
    }

    private static boolean hasLeadingByteOrderMark(byte[] data, ByteOrderMark byteOrderMark) {
        byte[] bom = byteOrderMark.getBytes();
        return data.length >= bom.length && Arrays.equals(data, 0, bom.length, bom, 0, bom.length);
    }
}
