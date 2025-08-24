package org.cloudfoundry.identity.uaa.provider.saml;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.bareCertificate1;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.bareCertificate2;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.bareLegacyCertificate;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.keyName1;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.keyName2;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.keyName3;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.legacyCertificate;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.legacyKey;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.legacyKeyName;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.legacyPassphrase;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.legacySamlKey;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.samlKey1;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.samlKey2;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.samlKeyCertOnly;

class SamlKeyManagerFactoryTests {

    private SamlKeyManagerFactory samlKeyManagerFactory;
    private SamlConfig config;

    private final SamlConfigProps samlConfigProps = new SamlConfigProps();

    @BeforeAll
    static void beforeAll() {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    @BeforeEach
    void beforeEach() {
        IdentityZoneHolder.clear();
        config = new SamlConfig();
        config.setPrivateKey(legacyKey());
        config.setCertificate(legacyCertificate());
        config.setPrivateKeyPassword(legacyPassphrase());

        config.addKey(keyName1(), samlKey1());
        config.addKey(keyName2(), samlKey2());

        samlKeyManagerFactory = new SamlKeyManagerFactory(samlConfigProps);
    }

    @AfterAll
    static void afterAll() {
        IdentityZoneHolder.clear();
    }

    @Test
    void withKeysInSamlConfig_Returns_SamlConfigSamlKeyManagerImpl() {
        SamlKeyManager manager = samlKeyManagerFactory.getKeyManager(config);
        assertThat(manager).isInstanceOf(SamlKeyManagerFactory.SamlConfigSamlKeyManagerImpl.class);
        assertThat(manager.getDefaultCredentialName()).isEqualTo(legacyKeyName());
        assertThat(manager.getAvailableCredentials())
                .hasSize(3)
                .extracting(KeyWithCert::getEncodedCertificate)
                .contains(bareLegacyCertificate(), bareCertificate1(), bareCertificate2())
                .first()
                .isEqualTo(bareLegacyCertificate());
        assertThat(manager.getAvailableCredentialIds())
                .contains(legacyKeyName(), keyName1(), keyName2())
                .first()
                .isEqualTo(legacyKeyName());

        assertThat(manager.getDefaultCredential().getCertificate())
                .isEqualTo(manager.getCredential(legacyKeyName()).getCertificate());
        assertThat(manager.getCredential("notFound")).isNull();
    }

    @Test
    void withNoKeysInSamlConfig_FallsBackTo_SamlConfigPropsSamlKeyManagerImpl() {
        samlConfigProps.setKeys(Map.of(legacyKeyName(), legacySamlKey(),
                keyName1(), samlKey1(),
                keyName2(), samlKey2()));
        samlConfigProps.setActiveKeyId(legacyKeyName());

        SamlKeyManager manager = samlKeyManagerFactory.getKeyManager(new SamlConfig());
        assertThat(manager).isInstanceOf(SamlKeyManagerFactory.SamlConfigPropsSamlKeyManagerImpl.class);
        assertThat(manager.getDefaultCredentialName()).isEqualTo(legacyKeyName());
        assertThat(manager.getAvailableCredentials())
                .hasSize(3)
                .extracting(KeyWithCert::getEncodedCertificate)
                .contains(bareLegacyCertificate(), bareCertificate1(), bareCertificate2())
                .first()
                .isEqualTo(bareLegacyCertificate());
        assertThat(manager.getAvailableCredentialIds())
                .contains(legacyKeyName(), keyName1(), keyName2())
                .first()
                .isEqualTo(legacyKeyName());

        assertThat(manager.getDefaultCredential().getCertificate())
                .isEqualTo(manager.getCredential(legacyKeyName()).getCertificate());
        assertThat(manager.getCredential("notFound")).isNull();
    }

    @Test
    void multipleKeysLegacyIsActiveKey() {
        SamlKeyManager manager = samlKeyManagerFactory.getKeyManager(config);
        assertThat(manager.getDefaultCredentialName()).isEqualTo(legacyKeyName());
        assertThat(manager.getAvailableCredentials()).hasSize(3);
        assertThat(manager.getAvailableCredentialIds())
                .contains(legacyKeyName(), keyName1(), keyName2())
                .first()
                .isEqualTo(legacyKeyName());
        assertThat(manager.getCredential(keyName1())).isNotNull();
        assertThat(manager.getCredential("notFound")).isNull();
    }

    @Test
    void multipleKeysWithActiveKey() {
        config.setActiveKeyId(keyName1());

        SamlKeyManager manager = samlKeyManagerFactory.getKeyManager(config);
        assertThat(manager.getDefaultCredentialName()).isEqualTo(keyName1());
        assertThat(manager.getAvailableCredentials()).hasSize(3);
        assertThat(manager.getAvailableCredentialIds())
                .containsOnly(legacyKeyName(), keyName1(), keyName2())
                .first()
                .isEqualTo(keyName1());
        assertThat(manager.getDefaultCredential().getCertificate())
                .isEqualTo(manager.getCredential(keyName1()).getCertificate());
    }

    @Test
    void addActiveKey() {
        config.addAndActivateKey(keyName3(), samlKey1());
        SamlKeyManager manager = samlKeyManagerFactory.getKeyManager(config);
        assertThat(manager.getDefaultCredentialName()).isEqualTo(keyName3());
        assertThat(manager.getAvailableCredentials()).hasSize(4);
        assertThat(manager.getAvailableCredentialIds())
                .containsOnly(legacyKeyName(), keyName1(), keyName2(), keyName3())
                .first()
                .isEqualTo(keyName3());
    }

    @Test
    void multipleKeysWithActiveKeyInOtherZone() {
        IdentityZoneHolder.set(MultitenancyFixture.identityZone("other-zone-id", "domain"));
        config.setActiveKeyId(keyName1());
        SamlKeyManager manager = samlKeyManagerFactory.getKeyManager(config);
        assertThat(manager.getDefaultCredentialName()).isEqualTo(keyName1());
        assertThat(manager.getAvailableCredentials()).hasSize(3);
        assertThat(manager.getAvailableCredentialIds())
                .containsOnly(legacyKeyName(), keyName1(), keyName2())
                .first()
                .isEqualTo(keyName1());
    }

    @Test
    void addCertsKeysOnly() {
        config.setKeys(new HashMap<>());
        config.addAndActivateKey("cert-only", samlKeyCertOnly());
        SamlKeyManager manager1 = samlKeyManagerFactory.getKeyManager(config);
        assertThat(manager1.getDefaultCredential()).isNotNull();
        assertThat(manager1.getDefaultCredential().getPrivateKey()).isNull();
    }
}
