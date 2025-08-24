package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.user.MockUaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.sql.SQLException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class CheckIdpEnabledAuthenticationManagerTest {

    private IdentityProviderProvisioning identityProviderProvisioning;
    private CheckIdpEnabledAuthenticationManager manager;
    private UsernamePasswordAuthenticationToken token;

    @BeforeEach
    void setupAuthManager(@Autowired JdbcTemplate jdbcTemplate) throws SQLException {
        TestUtils.cleanAndSeedDb(jdbcTemplate);
        identityProviderProvisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        MockUaaUserDatabase userDatabase = new MockUaaUserDatabase(u -> u.withId("id").withUsername("marissa").withEmail("test@test.org").withVerified(true).withPassword("koala"));
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        when(encoder.matches(anyString(), anyString())).thenReturn(true);
        AuthzAuthenticationManager authzAuthenticationManager = new AuthzAuthenticationManager(userDatabase, encoder, identityProviderProvisioning, null);
        authzAuthenticationManager.setOrigin(OriginKeys.UAA);
        AccountLoginPolicy mockAccountLoginPolicy = mock(AccountLoginPolicy.class);
        when(mockAccountLoginPolicy.isAllowed(any(), any())).thenReturn(true);
        authzAuthenticationManager.setAccountLoginPolicy(mockAccountLoginPolicy);

        manager = new CheckIdpEnabledAuthenticationManager(authzAuthenticationManager, OriginKeys.UAA, identityProviderProvisioning);
        token = new UsernamePasswordAuthenticationToken("marissa", "koala");
    }

    @Test
    void authenticate() {
        Authentication auth = manager.authenticate(token);
        assertThat(auth).isNotNull();
        assertThat(auth.isAuthenticated()).isTrue();
    }

    @Test
    void authenticateIdpDisabled() {
        IdentityProvider provider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZoneHolder.get().getId());
        provider.setActive(false);
        identityProviderProvisioning.update(provider, IdentityZoneHolder.get().getId());
        assertThatExceptionOfType(ProviderNotFoundException.class).isThrownBy(() -> manager.authenticate(token));
    }

}
