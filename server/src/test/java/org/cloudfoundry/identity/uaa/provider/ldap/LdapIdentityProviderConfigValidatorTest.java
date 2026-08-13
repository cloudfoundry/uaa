/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider.ldap;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.Security;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class LdapIdentityProviderConfigValidatorTest {

    LdapIdentityProviderConfigValidator validator;

    @BeforeAll
    static void addProvider() {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    @BeforeEach
    void setup() {
        validator = spy(new LdapIdentityProviderConfigValidator());
    }

    @Test
    void null_identity_provider() {
        assertThatThrownBy(() -> validator.validate((IdentityProvider<AbstractIdentityProviderDefinition>) null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Provider cannot be null");
    }

    @Test
    void invalid_ldap_origin() {
        IdentityProvider<LdapIdentityProviderDefinition> ldap = new IdentityProvider<>();
        ldap.setType(LDAP);
        ldap.setOriginKey("other");
        assertThatThrownBy(() -> validator.validate(ldap))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("LDAP provider originKey must be set to '%s'".formatted(LDAP));
    }

    @Test
    void valid_ldap_origin() {
        IdentityProvider<LdapIdentityProviderDefinition> ldap = new IdentityProvider<>();
        ldap.setType(LDAP);
        ldap.setOriginKey(LDAP);
        doNothing().when(validator).validate(any(AbstractIdentityProviderDefinition.class));
        validator.validate(ldap);
        verify(validator, times(1)).validate((AbstractIdentityProviderDefinition) isNull());
    }

    // openssl req -out cert.pem -nodes -keyout private.key -newkey rsa:2048 -new -x509
    private static final String VALID_CERT = """
            -----BEGIN CERTIFICATE-----
            MIIDXTCCAkWgAwIBAgIJAOpOBuLToBXJMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
            BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
            aWRnaXRzIFB0eSBMdGQwHhcNMTcwNzE0MTcxNDE4WhcNMTcwODEzMTcxNDE4WjBF
            MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
            ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
            CgKCAQEA3+07F4S5Fz3wv/UFm/OWsJXm6s3pKI2mp4fSAY8rx9+0cyLAHsedWzeq
            5uKcDeRW858DOdnClaTOZC73FcvOmv1bw2eYcmfsbqHEhyR0dp+rDHt/7pr6kajC
            yUvAW+hoRRSMpooiZckxrjJ7LOa5iqRyZRwshfGN+mFSygfVguMDKrsE2rvpK6/K
            tkG/lcToLHiw4OnMnZ9ocrNRDAoCkzKGZTLJkUEr3MgOKmr2EO0P6KOAmNnOEmCf
            05ohcrUXeFZVnS5MMUzoGAOzBstZhA0dd7l297IDnWH9uIhCANCvZ9sovZWz/o3J
            pc2LyXsaI1cV7O1cGV4aEEn8zzWWGwIDAQABo1AwTjAdBgNVHQ4EFgQUXBO1+qo7
            w6iiiv1pnm+zdrQ3CzkwHwYDVR0jBBgwFoAUXBO1+qo7w6iiiv1pnm+zdrQ3Czkw
            DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAT78lT5VEIetWPGk3szPz
            CT9zNpR1F+7o3rvRTI6Psyjz4tGlyX5iU0Z99Xa9yimIEhWme2UVsgQ9uOzk2IgH
            wMbB2TTP/RRK5+eO4BUu4zWWIXsIcfC6Rqw9Y3Hki+mRpuWMv+5pcOz/H+aYeSfy
            WvVYfRZJOhcztysII4HWIxw8qqwBrf5kX8IRKZXay+A2W04A6kjjX3zfN2OzljTA
            jZbtHedUGxSHvK8x6tHEwS0lZ9eZh+V4DWyRvrunwDCtA7zJQmrJd1qbM84H/1C8
            cAC6dglvc82n1BTAZbZwWHYt+Ro3Vp0GMPsZLOXJ0g03LbkhXg4krwXjJPD42nus
            3A==
            -----END CERTIFICATE-----
            """;

    @Test
    void validate_definition_withValidCaCertificates_doesNotThrow() {
        LdapIdentityProviderDefinition definition = new LdapIdentityProviderDefinition();
        definition.setCaCertificates(List.of(VALID_CERT));
        assertThatCode(() -> validator.validate((AbstractIdentityProviderDefinition) definition)).doesNotThrowAnyException();
    }

    @Test
    void validate_definition_withMalformedCaCertificate_throws() {
        LdapIdentityProviderDefinition definition = new LdapIdentityProviderDefinition();
        definition.setCaCertificates(List.of("not a pem certificate"));
        assertThatThrownBy(() -> validator.validate((AbstractIdentityProviderDefinition) definition))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void validate_definition_withNoCaCertificates_doesNotThrow() {
        LdapIdentityProviderDefinition definition = new LdapIdentityProviderDefinition();
        assertThatCode(() -> validator.validate((AbstractIdentityProviderDefinition) definition)).doesNotThrowAnyException();
    }
}
