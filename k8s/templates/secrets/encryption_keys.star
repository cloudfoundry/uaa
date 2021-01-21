load("@ytt:assert", "assert")

def validated_encryption_keys(encryption):
    if not encryption or not hasattr(encryption, "active_key_label") or not encryption.active_key_label:
        assert.fail("encryption.active_key_label is required")
    end

    active_keys = []
    for key in encryption.encryption_keys:
        if key.label == encryption.active_key_label:
            active_keys.append(key)
        end
    end

    if not active_keys:
        assert.fail("encryption.active_key_label must reference key in encryption.encryption_keys")
    end

    return encryption
end