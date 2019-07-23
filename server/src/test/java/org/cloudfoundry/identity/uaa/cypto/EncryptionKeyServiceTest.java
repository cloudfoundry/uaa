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
    private List<EncryptionKey> encryptionKeys;

    @Before
    public void setup() {
        encryptionKeys = new ArrayList<>();
        encryptionKeys.add(new EncryptionKey("active-key","some-passphrase" ));
        encryptionKeys.add(new EncryptionKey("active-key2", "\"some-passphrase2\""));
        EncryptionProperties properties = new EncryptionProperties();
        properties.setActiveKeyLabel("active-key");
        properties.setEncryptionKeys(encryptionKeys);
        encryptionKeyService = new EncryptionKeyService(properties);
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

        EncryptionProperties properties = new EncryptionProperties();
        properties.setActiveKeyLabel(activeKeyLabel);
        properties.setEncryptionKeys(new ArrayList<>());

        encryptionKeyService = new EncryptionKeyService(properties);
    }

    @Test
    public void shouldThrowErrorIfNoActiveKeyLabelIsProvided() {
        expectedException.expect(NoActiveEncryptionKeyProvided.class);
        expectedException.expectMessage("UAA cannot be started without encryption key value uaa.encryption.active_key_label");

        EncryptionProperties properties = new EncryptionProperties();
        properties.setActiveKeyLabel("");
        properties.setEncryptionKeys(new ArrayList<>());

        encryptionKeyService = new EncryptionKeyService(properties);
    }

    @Test
    public void shouldThrowErrorIfPassphraseIsLessThan8Characters() {
        expectedException.expect(NoActiveEncryptionKeyProvided.class);
        expectedException.expectMessage("The required length of the encryption passphrases for [label=key-1, label=key-2] need to be at least 8 characters long.");

        List<EncryptionKey> keys = Lists.newArrayList(
           new EncryptionKey("key-1", "a"),
           new EncryptionKey("key-2", "aaaaaaa"),
           new EncryptionKey("key-3", "aaaaaaaa")
        );

        EncryptionProperties properties = new EncryptionProperties();
        properties.setActiveKeyLabel("key-1");
        properties.setEncryptionKeys(keys);

        encryptionKeyService = new EncryptionKeyService(properties);
    }

    @Test
    public void shouldThrowErrorIfDuplicateKeysAreProvided() {
        expectedException.expect(NoActiveEncryptionKeyProvided.class);
        expectedException.expectMessage("UAA cannot be started as multiple keys have the same label in uaa.encryption.encryption_keys/[label=key-1]");

        EncryptionKey key1 = new EncryptionKey("key-1", Strings.repeat("a", 8));

        EncryptionProperties properties = new EncryptionProperties();
        properties.setActiveKeyLabel("key-1");
        properties.setEncryptionKeys(Lists.newArrayList(key1, key1));

        encryptionKeyService = new EncryptionKeyService(properties);
    }

    @Test
    public void eachEncryptionKeyShouldHaveANonEmptyPassphrase() {
        String key2 = "key2" + System.currentTimeMillis();
        String key3 = "key3" + System.currentTimeMillis();

        expectedException.expect(NoActiveEncryptionKeyProvided.class);
        expectedException.expectMessage(
          String.format("UAA cannot be started as encryption key passphrase for uaa.encryption.encryption_keys/[label=%s, label=%s] is undefined", key2, key3)
        );

        EncryptionKey activeEncryptionKey = new EncryptionKey("key1", "123456789");
        EncryptionKey encryptionKey2 = new EncryptionKey(key2, "");
        EncryptionKey encryptionKey3 = new EncryptionKey(key3, "");

        EncryptionProperties properties = new EncryptionProperties();
        properties.setActiveKeyLabel("key1");
        properties.setEncryptionKeys(Lists.newArrayList(activeEncryptionKey, encryptionKey2, encryptionKey3));

        encryptionKeyService = new EncryptionKeyService(properties);
    }

    @Test
    public void shouldBeAbleToFetchInactiveKey() {
        Optional<EncryptionKey> key = encryptionKeyService.getKey("active-key2");
        assertThat(key.isPresent(), is(true));
        assertThat(key.get().getLabel(), is("active-key2"));
        assertThat(key.get().getPassphrase(), is("some-passphrase2"));
    }

    @Test
    public void shouldThrowAMeaningfulErrorWhenUnableToFindAKey() {
        Optional<EncryptionKey> missingKey = encryptionKeyService.getKey("key-that-does-not-exist");
        assertThat(missingKey.isPresent(), is(false));
    }
}
