package org.cloudfoundry.identity.uaa.cypto;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

public class ActiveEncryptionKeyServiceTest {
    private ActiveEncryptionKeyService activeEncryptionKeyService;
    private List<ActiveEncryptionKeyService.EncryptionKey> encryptionKeys;

    @Before
    public void setup() {
        encryptionKeys = new ArrayList<>();
        encryptionKeys.add(new ActiveEncryptionKeyService.EncryptionKey() {{
            put("label", "active-key");
            put("passphrase", "some-passphrase");
        }});

        encryptionKeys.add(new ActiveEncryptionKeyService.EncryptionKey() {{
            put("label", "active-key2");
            put("passphrase", "some-passphrase2");
        }});

        activeEncryptionKeyService = new ActiveEncryptionKeyService("active-key", encryptionKeys);
    }

    @Test
    public void shouldFetchValidEncryptionActiveKeyPassphrase() {
        String passphrase = activeEncryptionKeyService.getPassphrase();

        assertThat(passphrase, is("some-passphrase"));
    }

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void shouldThrowErrorIfActiveEncryptionKeyHasNotBeenProvided() {
        expectedException.expect(NoActiveEncryptionKeyProvided.class);
        expectedException.expectMessage("active-key was not provided as an encryption key");

        activeEncryptionKeyService = new ActiveEncryptionKeyService("active-key", new ArrayList<>());
    }
}