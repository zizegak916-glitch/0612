package com.fool.ipbatch;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Stores subscription URLs and API keys encrypted by a non-exportable Android Keystore key. */
public final class SecretStore {
    private static final String ALIAS = "ip_batch_inspector_secrets_v2";
    private static final String PREFIX = "encrypted_";
    private final SharedPreferences prefs;

    public SecretStore(Context context) {
        prefs = context.getSharedPreferences("secure_values", Context.MODE_PRIVATE);
    }

    public void put(String name, String value) throws Exception {
        if (value == null || value.isEmpty()) {
            prefs.edit().remove(PREFIX + name).apply();
            return;
        }
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key());
        byte[] encrypted = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
        byte[] iv = cipher.getIV();
        byte[] joined = new byte[1 + iv.length + encrypted.length];
        joined[0] = (byte) iv.length;
        System.arraycopy(iv, 0, joined, 1, iv.length);
        System.arraycopy(encrypted, 0, joined, 1 + iv.length, encrypted.length);
        prefs.edit().putString(PREFIX + name, Base64.encodeToString(joined, Base64.NO_WRAP)).apply();
    }

    public String get(String name) {
        String encoded = prefs.getString(PREFIX + name, "");
        if (encoded == null || encoded.isEmpty()) return "";
        try {
            byte[] joined = Base64.decode(encoded, Base64.NO_WRAP);
            int ivLength = joined[0] & 255;
            if (ivLength < 12 || 1 + ivLength >= joined.length) throw new Exception("invalid encrypted value");
            byte[] iv = new byte[ivLength];
            byte[] encrypted = new byte[joined.length - 1 - ivLength];
            System.arraycopy(joined, 1, iv, 0, ivLength);
            System.arraycopy(joined, 1 + ivLength, encrypted, 0, encrypted.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, iv));
            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        } catch (Exception ignored) {
            return "";
        }
    }

    public boolean contains(String name) {
        return prefs.contains(PREFIX + name);
    }

    public void remove(String name) {
        prefs.edit().remove(PREFIX + name).apply();
    }

    private SecretKey key() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (store.containsAlias(ALIAS)) return ((KeyStore.SecretKeyEntry) store.getEntry(ALIAS, null)).getSecretKey();
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build());
        return generator.generateKey();
    }
}
