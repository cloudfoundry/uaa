package org.cloudfoundry.identity.uaa.cypto;

import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

public class EncryptionKeyServiceTest {
    private EncryptionKeyService encryptionKeyService;
    private List<EncryptionKeyService.EncryptionKey> encryptionKeys;

    @Before
    public void setup() {
        encryptionKeys = new ArrayList<>();
        encryptionKeys.add(new EncryptionKeyService.EncryptionKey() {{
            put("label", "active-key");
            put("passphrase", "some-passphrase");
        }});

        encryptionKeys.add(new EncryptionKeyService.EncryptionKey() {{
            put("label", "active-key2");
            put("passphrase", "some-passphrase2");
        }});

        encryptionKeyService = new EncryptionKeyService("active-key", encryptionKeys);
    }

    @Test
    public void shouldFetchValidEncryptionActiveKeyPassphrase() throws EncryptionServiceException {
        String passphrase = encryptionKeyService.getActiveKey().getPassphrase();

        assertThat(passphrase, is("some-passphrase"));
        byte[] cipherValue = encryptionKeyService.getActiveKey().encrypt("plain-text");
        assertThat(cipherValue, is(notNullValue()));
        assertThat(new String(encryptionKeyService.getActiveKey().decrypt(cipherValue)), is("plain-text"));
    }

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void shouldThrowErrorIfActiveEncryptionKeyHasNotBeenProvided() {
        String activeKeyLabel = "active-key" + System.currentTimeMillis();
        expectedException.expect(NoActiveEncryptionKeyProvided.class);
        expectedException.expectMessage(String.format("UAA cannot be started as encryption key passphrase for uaa.encryption.encryption_keys/[label=%s] is undefined", activeKeyLabel));

        encryptionKeyService = new EncryptionKeyService(activeKeyLabel, new ArrayList<>());
    }

    @Test
    public void shouldThrowErrorIfNoActiveKeyLabelIsProvided() {
        expectedException.expect(NoActiveEncryptionKeyProvided.class);
        expectedException.expectMessage("UAA cannot be started without encryption key value uaa.encryption.active_key_label");

        encryptionKeyService = new EncryptionKeyService("", new ArrayList<>());
    }

    @Test
    public void shouldThrowErrorIfPassphraseIsLessThan8Characters() {
        expectedException.expect(NoActiveEncryptionKeyProvided.class);
        expectedException.expectMessage("The required length of the encryption passphrases for [label=key-1, label=key-2] need to be at least 8 characters long.");

        encryptionKeyService = new EncryptionKeyService("key-1", Lists.newArrayList(new EncryptionKeyService.EncryptionKey() {{
            put("label", "key-1");
            put("passphrase", "a");
        }}, new EncryptionKeyService.EncryptionKey() {{
            put("label", "key-2");
            put("passphrase", "aaaaaaa");
        }}, new EncryptionKeyService.EncryptionKey() {{
            put("label", "key-3");
            put("passphrase", "aaaaaaaa");
        }}));
    }

    @Test
    public void shouldThrowErrorIfDuplicateKeysAreProvided() {
        expectedException.expect(NoActiveEncryptionKeyProvided.class);
        expectedException.expectMessage("UAA cannot be started as multiple keys have the same label in uaa.encryption.encryption_keys/[label=key-1]");

        EncryptionKeyService.EncryptionKey key1 = new EncryptionKeyService.EncryptionKey() {{
            put("label", "key-1");
            put("passphrase", Strings.repeat("a", 8));
        }};

        encryptionKeyService = new EncryptionKeyService("key-1", Lists.newArrayList(key1, key1));
    }

    @Test
    public void eachEncryptionKeyShouldHaveANonEmptyPassphrase() {
        String key2 = "key2" + System.currentTimeMillis();
        String key3 = "key3" + System.currentTimeMillis();

        expectedException.expect(NoActiveEncryptionKeyProvided.class);
        expectedException.expectMessage(
          String.format("UAA cannot be started as encryption key passphrase for uaa.encryption.encryption_keys/[label=%s, label=%s] is undefined", key2, key3)
        );

        EncryptionKeyService.EncryptionKey activeEncryptionKey = new EncryptionKeyService.EncryptionKey();
        activeEncryptionKey.put("label", "key1");
        activeEncryptionKey.put("passphrase", "123456789");

        EncryptionKeyService.EncryptionKey encryptionKey2 = new EncryptionKeyService.EncryptionKey();
        encryptionKey2.put("label", key2);
        encryptionKey2.put("passphrase", "");


        EncryptionKeyService.EncryptionKey encryptionKey3 = new EncryptionKeyService.EncryptionKey();
        encryptionKey3.put("label", key3);
        encryptionKey3.put("passphrase", "");

        encryptionKeyService =
          new EncryptionKeyService("key1", Lists.newArrayList(activeEncryptionKey, encryptionKey2, encryptionKey3));
    }

    @Test
    public void shouldBeAbleToFetchInactiveKey() {
        Optional<EncryptionKeyService.EncryptionKey> key = encryptionKeyService.getKey("active-key2");
        assertThat(key.isPresent(), is(true));

        assertThat(key.get().getLabel(), is("active-key2"));
        assertThat(key.get().getPassphrase(), is("some-passphrase2"));
    }

    @Test
    public void shouldThrowAMeaningfulErrorWhenUnableToFindAKey() {
        Optional<EncryptionKeyService.EncryptionKey> missingKey = encryptionKeyService.getKey("key-that-does-not-exist");

        assertThat(missingKey.isPresent(), is(false));
    }
}
