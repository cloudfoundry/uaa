package org.cloudfoundry.identity.uaa.zone;

import static java.util.Optional.ofNullable;
import static org.springframework.util.StringUtils.hasLength;
import static org.springframework.util.StringUtils.hasText;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.client.ClientAdminEndpointsValidator;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.SamlConfig.SignatureAlgorithm;
import org.cloudfoundry.identity.uaa.zone.model.ConnectionDetails;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneHeader;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneRequest;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.web.util.UriComponentsBuilder;

public class OrchestratorZoneService implements ApplicationEventPublisherAware {

    public static final String X_IDENTITY_ZONE_ID = "X-Identity-Zone-Id";
    public static final String GENERATED_KEY_ID = "generated-saml-key";
    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";

    public static final String CLIENT_ID = "admin";
    public static final String ZONE_AUTHORITIES =
        "clients.admin,clients.read,clients.write,clients.secret,idps.read,idps.write,sps" +
        ".read,sps.write,scim.read,scim.write,uaa.resource";
    public static final String GRANT_TYPES = "client_credentials";
    public static final String RESOURCE_IDS = "none";
    public static final String SCOPES = "uaa.none";
    public static final String ZONE_CREATED_MESSAGE = "Zone Created Successfully";
    public static final String ZONE_DELETED_MESSAGE = "Zone Deleted Successfully";

    private static final java.util.Base64.Encoder base64encoder = java.util.Base64.getMimeEncoder(64, "\n".getBytes());
    public static final String DASHBOARD_LOGIN_PATH = "/#/login/";

    private final IdentityZoneProvisioning zoneProvisioning;
    private final IdentityProviderProvisioning idpProvisioning;
    private final ScimGroupProvisioning groupProvisioning;
    private final QueryableResourceManager<ClientDetails> clientDetailsService;
    private final ClientAdminEndpointsValidator clientDetailsValidator;
    private final String uaaDashboardUri;
    private final String uaaUrl;
    private final String issuerUri;

    private ApplicationEventPublisher publisher;

    private SignatureAlgorithm defaultSamlSignatureAlgorithm;

    private static final Logger logger = LoggerFactory.getLogger(OrchestratorZoneService.class);

    public OrchestratorZoneService(IdentityZoneProvisioning zoneProvisioning,
                                   IdentityProviderProvisioning idpProvisioning,
                                   ScimGroupProvisioning groupProvisioning,
                                   QueryableResourceManager<ClientDetails> clientDetailsService,
                                   ClientAdminEndpointsValidator clientDetailsValidator,
                                   String uaaDashboardUri, String uaaUrl,
                                   String issuerUri
                                  ) {
        this.zoneProvisioning = zoneProvisioning;
        this.idpProvisioning = idpProvisioning;
        this.groupProvisioning = groupProvisioning;
        this.clientDetailsService = clientDetailsService;
        this.clientDetailsValidator = clientDetailsValidator;
        this.uaaDashboardUri = uaaDashboardUri;
        this.uaaUrl = uaaUrl;
        this.issuerUri = issuerUri;
    }

    @Autowired
    public void setDefaultSamlSignatureAlgorithm(@Qualifier("globalSamlSignatureAlgorithm") SignatureAlgorithm samlSignatureAlgorithm) {
        this.defaultSamlSignatureAlgorithm = samlSignatureAlgorithm;
    }

    public OrchestratorZoneResponse getZoneDetails(String zoneName) {
        OrchestratorZoneEntity orchestratorZone = zoneProvisioning.retrieveByName(zoneName);
        ConnectionDetails connectionDetails = buildConnectionDetails(orchestratorZone);
        OrchestratorZoneResponse response = new OrchestratorZoneResponse();
        response.setName(zoneName);
        response.setConnectionDetails(connectionDetails);
        response.setMessage("");
        response.setState(OrchestratorState.FOUND.toString());
        return response;
    }

    public OrchestratorZoneResponse deleteZone(String zoneName) {
        IdentityZone previous = IdentityZoneHolder.get();
        try {
            logger.debug("Zone - deleting Name[" + zoneName + "]");
            OrchestratorZoneEntity orchestratorZone = zoneProvisioning.retrieveByName(zoneName);
            IdentityZone zone = zoneProvisioning.retrieve(orchestratorZone.getIdentityZoneId());
            IdentityZoneHolder.set(zone);
            if (publisher != null && zone != null) {
                zoneProvisioning.deleteOrchestratorZone(zoneName);
                publisher.publishEvent(
                    new EntityDeletedEvent<>(zone, SecurityContextHolder.getContext().getAuthentication(),
                                             IdentityZoneHolder.getCurrentZoneId()));
                logger.debug("Zone - deleted id[" + zone.getId() + "]");
            } else {
                throw new OrchestratorZoneServiceException(zoneName, "Error : deleting zone Name[" + zoneName + "]");
            }
        } finally {
            IdentityZoneHolder.set(previous);
        }

        OrchestratorZoneResponse response = new OrchestratorZoneResponse();
        response.setName(zoneName);
        response.setMessage(ZONE_DELETED_MESSAGE);
        response.setState(OrchestratorState.DELETE_IN_PROGRESS.toString());
        return response;
    }

    private ConnectionDetails buildConnectionDetails(OrchestratorZoneEntity orchestratorZone) {
        ConnectionDetails connectionDetails = new ConnectionDetails();
        connectionDetails.setUri(constructUri(orchestratorZone.getSubdomain(), uaaUrl, ""));
        connectionDetails.setIssuerId(constructUri(orchestratorZone.getSubdomain(), issuerUri, "oauth/token"));
        connectionDetails.setSubdomain(orchestratorZone.getSubdomain());
        connectionDetails.setDashboardUri(uaaDashboardUri + DASHBOARD_LOGIN_PATH + orchestratorZone.getIdentityZoneId());
        OrchestratorZoneHeader zoneHeader = new OrchestratorZoneHeader(X_IDENTITY_ZONE_ID, orchestratorZone.getIdentityZoneId());
        connectionDetails.setZone(zoneHeader);
        return connectionDetails;
    }

    private String constructUri(String subDomain, String baseUrl, String path) {
        URI uri = URI.create(baseUrl);
        String hostToUse = uri.getHost();
        if (hasText(subDomain)) {
            hostToUse = subDomain + "." + hostToUse;
        }
        return UriComponentsBuilder.fromUri(uri).host(hostToUse).pathSegment(path).build().toUriString();
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

    public OrchestratorZoneResponse createZone(OrchestratorZoneRequest zoneRequest) {
        if (!IdentityZoneHolder.isUaa()) {
            throw new AccessDeniedException("Zones can only be created by being authenticated in the default zone.");
        }
        String name = zoneRequest.getName();
        String adminClientSecret = zoneRequest.getParameters().getAdminClientSecret();

        String subdomain = zoneRequest.getParameters().getSubdomain();
        String id = UUID.randomUUID().toString();
        subdomain = getSubDomain(subdomain, id);

        IdentityZone identityZone = generateIdentityZone(subdomain, name, id);

        IdentityZone previous = IdentityZoneHolder.get();
        try {
            IdentityZone created = createIdentityZone(identityZone);
            // This DAO method will throw ConstraintViolationException
            // if there is a duplicate entry in orchestrator_zone table
            zoneProvisioning.createOrchestratorZone(identityZone.getId(), name);
            IdentityZoneHolder.set(created);
            createDefaultIdp(created);
            createUserGroups(created);
            createZoneAdminClient(adminClientSecret, created);
        } finally {
            IdentityZoneHolder.set(previous);
        }

        OrchestratorZoneResponse response = new OrchestratorZoneResponse();
        response.setName(zoneRequest.getName());
        response.setMessage(ZONE_CREATED_MESSAGE);
        response.setState(OrchestratorState.CREATE_IN_PROGRESS.toString());
        return response;
    }

    private String getSubDomain(String subdomain, String id) {
        if (subdomain == null) {
            subdomain = id;
        }
        return subdomain;
    }

    private void createZoneAdminClient(String adminClientSecret, IdentityZone created) {
        String zoneId = IdentityZoneHolder.get().getId();
        String authorities = ZONE_AUTHORITIES + ",zones." + zoneId + ".admin";
        try {
            createZoneAdminClient(created.getId(), authorities, CLIENT_ID, adminClientSecret, GRANT_TYPES, RESOURCE_IDS,
                                  SCOPES);
        } catch (Exception e) {
            String errorMessage = String.format("Unable to create client for zone name : %s  failed.", created.getName());
            logger.error(errorMessage, e);
            throw new OrchestratorZoneServiceException(created.getName(), errorMessage+" Exception is :" + e.getMessage());
        }
    }

    private void createDefaultIdp(IdentityZone created) {
        try {
            IdentityProvider defaultIdp = new IdentityProvider();
            defaultIdp.setName(OriginKeys.UAA);
            defaultIdp.setType(OriginKeys.UAA);
            defaultIdp.setOriginKey(OriginKeys.UAA);
            defaultIdp.setIdentityZoneId(created.getId());
            UaaIdentityProviderDefinition idpDefinition = new UaaIdentityProviderDefinition();
            idpDefinition.setPasswordPolicy(null);
            defaultIdp.setConfig(idpDefinition);
            idpProvisioning.create(defaultIdp, created.getId());
            logger.debug("Created default IDP in zone - created zone name [" + created.getName() + "]");
        } catch (Exception e) {
            String errorMessage = String.format(
                "Unable to create identity provider for zone name : %s",
                created.getName());
            logger.error(errorMessage, e);
            throw new OrchestratorZoneServiceException(created.getName(), errorMessage + " Exception is : " + e.getMessage());
        }
    }

    private IdentityZone createIdentityZone(IdentityZone identityZone) {
        IdentityZone created = null;
        try {
            logger.debug("Zone - creating zone name [" + identityZone.getName() + "]");
            created = zoneProvisioning.create(identityZone);
            logger.debug("Zone - created zone name [" + identityZone.getName() + "]");
        } catch (ZoneAlreadyExistsException e) {
            String errorMessage = String.format("The subdomain name %s is already taken. Please use a different subdomain",
                                                identityZone.getSubdomain());
            logger.error(errorMessage, e);
            throw new ZoneAlreadyExistsException(identityZone.getName(), errorMessage, e);
        } catch (Exception e) {
            String errorMessage = String.format("Unexpected exception while creating identity zone for zone name : " +
                                                "%s", identityZone.getName());
            logger.error(errorMessage, e);
            throw new OrchestratorZoneServiceException(identityZone.getName(), errorMessage);
        }
        return created;
    }

    protected IdentityZone generateIdentityZone(String subdomain, String name, String id) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(id);
        identityZone.setName(name);
        identityZone.setSubdomain(subdomain);
        setTokenPolicy(createSigningKey(name), identityZone);
        setSamlConfig(identityZone);
        identityZone.getConfig().getLinks().getLogout().setWhitelist(createDeploymentSpecificLogoutWhiteList());
        identityZone.getConfig().getLinks().getSelfService().setSelfServiceCreateAccountEnabled(false);
        identityZone.getConfig().getLinks().getSelfService().setSignup("");
        identityZone.getConfig().getLinks().getSelfService().setSelfServiceResetPasswordEnabled(true);
        return identityZone;
    }

    private void setSamlConfig(IdentityZone identityZone) {
        try {
            identityZone.getConfig().setSamlConfig(createSamlConfig(identityZone.getSubdomain()));
        } catch (Exception e) {
            String errorMessage = String.format(
                "Unexpected exception while create saml config for zone name: %s",
                identityZone.getName());
            logger.error(errorMessage, e);
            throw new OrchestratorZoneServiceException(identityZone.getName(), errorMessage+ " Exception is : " + e.getMessage());
        }
    }

    private void setTokenPolicy(String zoneSigningKey, IdentityZone identityZone) {
        String activeKeyId = new RandomValueStringGenerator(5).generate();
        Map<String, String> keys = getKeys(zoneSigningKey, activeKeyId);
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setActiveKeyId(activeKeyId);
        tokenPolicy.setKeys(keys);
        identityZone.getConfig().setTokenPolicy(tokenPolicy);
    }

    private String createSigningKey(String zoneName) {
        StringWriter pemStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(pemStringWriter);
        try {
            KeyPairGenerator keyPairGenerator = null;
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            pemWriter.writeObject(keyPairGenerator.genKeyPair().getPrivate());
        } catch (Exception e) {
            logAndThrowException(zoneName, e);
        } finally {
            try {
                pemWriter.flush();
                pemWriter.close();
            } catch (IOException e) {
                logAndThrowException(zoneName, e);
            }
        }
        return pemStringWriter.toString();
    }

    private void logAndThrowException(String zoneName, Exception e) {
        String errorMessage = String.format(
            "Unexpected exception while create signingKey for zone name : %s",
            zoneName);
        logger.error(errorMessage, e);
        throw new OrchestratorZoneServiceException(zoneName, errorMessage + " Exception is : " + e.getMessage());
    }

    private void createZoneAdminClient(final String id, final String authorities, final String clientId,
                                       final String clientSecret,
                                       final String grantTypes, final String resourceIds, final String scopes) {
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, resourceIds, scopes, grantTypes, authorities);
        clientDetails.setClientSecret(clientSecret);
        ClientDetails details = clientDetailsValidator.validate(clientDetails, true, false);
        clientDetailsService.create(details, id);
    }

    private void createUserGroups(IdentityZone zone) {
        UserConfig userConfig = zone.getConfig().getUserConfig();
        if (userConfig != null) {
            List<String> defaultGroups = ofNullable(userConfig.getDefaultGroups()).orElse(Collections.emptyList());
            logger.debug(String.format("About to create default groups count: %s for zone name: %s",
                                       defaultGroups.size(), zone.getName()));
            for (String group : defaultGroups) {
                logger.debug(String.format("Creating zone default group: %s for zone name: %s", group,
                                           zone.getName()));
                groupProvisioning.createOrGet(
                    new ScimGroup(
                        null,
                        group,
                        zone.getId()
                    ),
                    zone.getId()
                                             );
            }
        }
    }

    private List<String>  createDeploymentSpecificLogoutWhiteList()
    {
        String runDomainFQDN = getRunDomainFromUAADomain();
        return (!hasLength(runDomainFQDN))  ? Collections.singletonList("http*://**") :
               Collections.singletonList("http*://**" + runDomainFQDN);
    }

    /**
     * Remove all characters till first dot
     */
    private String getRunDomainFromUAADomain() {
        if (!hasLength(uaaUrl))  return uaaUrl;
        int firstDotIndex = uaaUrl.indexOf('.');
        if (firstDotIndex == -1)  return "";
        return uaaUrl.substring(firstDotIndex);
    }


    private Map<String, String> getKeys(String zoneSigningKey, String activeKeyId) {
        Map<String, String> keysMap = new HashMap<>();
        Map<String, Map<String, String>> keys = new HashMap<>();
        Map<String, String> signingKeyMap = new HashMap<>();
        signingKeyMap.put("signingKey", zoneSigningKey);
        String keysStr = JsonUtils.writeValueAsString(signingKeyMap);
        keysMap.put(activeKeyId, keysStr);
        return keysMap;
    }

    private SamlConfig createSamlConfig(String subdomain)
        throws NoSuchAlgorithmException, IOException, OperatorCreationException {
        StringWriter pemStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(pemStringWriter);
        SamlConfig samlConfig = new SamlConfig();
        try {
            JcePEMEncryptorBuilder builder = new JcePEMEncryptorBuilder("DES-EDE3-CBC");
            builder.setProvider("BC");
            String passphrase = new RandomValueStringGenerator(8).generate();
            PEMEncryptor pemEncryptor = builder.build(passphrase.toCharArray());
            KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
            rsa.initialize(2048);
            KeyPair kp = rsa.generateKeyPair();

            JcaMiscPEMGenerator pemGenerator = new JcaMiscPEMGenerator(kp.getPrivate(), pemEncryptor);
            pemWriter.writeObject(pemGenerator);
            pemWriter.flush();

            Calendar cal = Calendar.getInstance();
            cal.add(Calendar.YEAR, 10);

            byte[] pk = kp.getPublic().getEncoded();
            SubjectPublicKeyInfo bcPk = SubjectPublicKeyInfo.getInstance(pk);
            String dn = "C=US, ST=CA, L=San Ramon, O=GE, OU=GE Digital, CN=PredixUAA"+subdomain;
            X509v1CertificateBuilder certGen = new X509v1CertificateBuilder(
                new X500Name(dn),
                BigInteger.ONE,
                new Date(),
                cal.getTime(),
                new X500Name(dn),
                bcPk
            );
            X509CertificateHolder certHolder = certGen
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate()));

            HashMap<String, SamlKey> samlKeys = new HashMap<>();

            String certificate = BEGIN_CERT + "\n" + base64encoder.encodeToString(certHolder.getEncoded()) + "\n" + END_CERT;

            samlKeys.put(GENERATED_KEY_ID, new SamlKey(pemStringWriter.toString(), passphrase, certificate));
            samlConfig.setKeys(samlKeys);
            samlConfig.setActiveKeyId(GENERATED_KEY_ID);
            if (samlConfig.getSignatureAlgorithm() == null) {
                samlConfig.setSignatureAlgorithm(defaultSamlSignatureAlgorithm);
            }
        } finally {
            pemWriter.flush();
            pemWriter.close();
        }
        return samlConfig;
    }
}
