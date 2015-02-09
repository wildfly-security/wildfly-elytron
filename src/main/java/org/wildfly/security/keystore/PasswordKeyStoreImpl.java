/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.keystore;

import static org.wildfly.security._private.ElytronMessages.log;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.PasswordUtil;
import org.wildfly.security.password.spec.PasswordSpec;

/**
 * A password file formatted {@link KeyStore} implementation.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class PasswordKeyStoreImpl extends KeyStoreSpi {
    private final AtomicReference<HashMap<String, PasswordEntry>> pwRef = new AtomicReference<>();

    public PasswordKeyStoreImpl() {
    }

    public Key engineGetKey(final String alias, final char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        final HashMap<String, PasswordEntry> map = pwRef.get();
        if (map == null) return null;
        final PasswordEntry key = map.get(alias);
        if (key == null) return null;
        if (password != null) {
            throw log.invalidKeyStoreEntryPassword(alias);
        }
        return key.getPassword();
    }

    public KeyStore.Entry engineGetEntry(final String alias, final KeyStore.ProtectionParameter protParam) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
        final HashMap<String, PasswordEntry> map = pwRef.get();
        if (map == null) return null;
        final PasswordEntry key = map.get(alias);
        if (key == null) return null;
        if (protParam != null) {
            throw log.invalidKeyStoreEntryPassword(alias);
        }
        return key;
    }

    public void engineSetEntry(final String alias, final KeyStore.Entry entry, final KeyStore.ProtectionParameter protParam) throws KeyStoreException {
        if (! (entry instanceof PasswordEntry)) {
            throw log.invalidKeyStoreEntryType(alias, PasswordEntry.class, entry.getClass());
        }
        if (protParam != null) {
            throw log.keyCannotBeProtected(alias);
        }
        HashMap<String, PasswordEntry> map, newMap;
        do {
            map = pwRef.get();
            if (map == null) {
                newMap = new LinkedHashMap<>(1);
            } else {
                newMap = new LinkedHashMap<>(map);
            }
            newMap.put(alias, (PasswordEntry) entry);
        } while (! pwRef.compareAndSet(map, newMap));
    }

    public boolean engineEntryInstanceOf(final String alias, final Class<? extends KeyStore.Entry> entryClass) {
        final HashMap<String, PasswordEntry> map = pwRef.get();
        return map != null && entryClass.isInstance(map.get(alias));
    }

    public Certificate[] engineGetCertificateChain(final String alias) {
        return null;
    }

    public Certificate engineGetCertificate(final String alias) {
        return null;
    }

    public Date engineGetCreationDate(final String alias) {
        return null;
    }

    public void engineSetKeyEntry(final String alias, final Key key, final char[] password, final Certificate[] chain) throws KeyStoreException {
        if (password != null) {
            throw new KeyStoreException(log.invalidKeyStoreEntryPassword(alias));
        }
        if (key instanceof Password) {
            engineSetEntry(alias, new PasswordEntry((Password) key), null);
        }
        throw log.invalidKeyStoreEntryType(alias, PasswordEntry.class, Key.class);
    }

    public void engineSetKeyEntry(final String alias, final byte[] key, final Certificate[] chain) throws KeyStoreException {
        throw log.invalidKeyStoreEntryType(alias, PasswordEntry.class, Key.class);
    }

    public void engineSetCertificateEntry(final String alias, final Certificate cert) throws KeyStoreException {
        throw log.invalidKeyStoreEntryType(alias, PasswordEntry.class, Certificate.class);
    }

    public void engineDeleteEntry(final String alias) throws KeyStoreException {
        HashMap<String, PasswordEntry> map, newMap;
        do {
            map = pwRef.get();
            if (map == null || ! map.containsKey(alias)) {
                return;
            }
            if (map.size() == 1) {
                newMap = null;
            } else {
                newMap = new LinkedHashMap<>(map);
                newMap.remove(alias);
            }
        } while (! pwRef.compareAndSet(map, newMap));
    }

    public Enumeration<String> engineAliases() {
        final HashMap<String, PasswordEntry> map = pwRef.get();
        return Collections.enumeration(map == null ? Collections.<String>emptySet() : map.keySet());
    }

    public boolean engineContainsAlias(final String alias) {
        final HashMap<String, PasswordEntry> map = pwRef.get();
        return map != null && map.containsKey(alias);
    }

    public int engineSize() {
        final HashMap<String, PasswordEntry> map = pwRef.get();
        return map == null ? 0 : map.size();
    }

    public boolean engineIsKeyEntry(final String alias) {
        return false;
    }

    public boolean engineIsCertificateEntry(final String alias) {
        return false;
    }

    public String engineGetCertificateAlias(final Certificate cert) {
        return null;
    }

    public void engineStore(final OutputStream stream, final char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        final HashMap<String, PasswordEntry> map = pwRef.get();
        if (map != null) {
            final OutputStreamWriter osw = new OutputStreamWriter(stream, StandardCharsets.UTF_8);
            final BufferedWriter bw = new BufferedWriter(osw);
            for (Map.Entry<String, PasswordEntry> entry : map.entrySet()) {
                final PasswordEntry passwordEntry = entry.getValue();
                final Password pw = passwordEntry.getPassword();
                final PasswordFactory factory = PasswordFactory.getInstance(pw.getAlgorithm());
                final PasswordSpec passwordSpec;
                final char[] chars;
                final String alias = entry.getKey();
                try {
                    passwordSpec = factory.getKeySpec(pw, PasswordSpec.class);
                    chars = PasswordUtil.getCryptStringChars(passwordSpec);
                } catch (InvalidKeySpecException e) {
                    throw log.keyStoreFailedToTranslate(alias, e);
                }

                bw.write(alias.replaceAll("([\\\\:])", "\\$1"));
                bw.write(':');
                bw.write(chars);
                bw.write('\n');
                // ensure that a broken file ends on a whole entry
                bw.flush();
            }
        }
    }

    private static int forceReadCP(Reader r) throws IOException {
        final int i = readCP(r);
        if (i == -1) {
            throw log.unexpectedEof();
        }
        return i;
    }

    private static int readCP(Reader r) throws IOException {
        int hi, lo;
        hi = r.read();
        if (hi == -1) {
            return -1;
        }
        if (Character.isHighSurrogate((char) hi)) {
            lo = r.read();
            if (lo == -1) throw log.unexpectedEof();
            if (Character.isLowSurrogate((char) lo)) {
                return Character.toCodePoint((char) hi, (char) lo);
            } else {
                throw new CharacterCodingException();
            }
        } else {
            return hi;
        }
    }

    public void engineLoad(final InputStream stream, final char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        final LinkedHashMap<String, PasswordEntry> map = new LinkedHashMap<String, PasswordEntry>();
        final InputStreamReader isr = new InputStreamReader(stream, StandardCharsets.UTF_8);
        final BufferedReader br = new BufferedReader(isr);
        int ch;
        StringBuilder b = new StringBuilder();
        String alias;
        outer: for (;;) {
            ch = readCP(br);
            if (ch == -1) {
                pwRef.set(map);
                return;
            }
            for (;;) {
                if (ch == '\\') {
                    ch = forceReadCP(br);
                    b.appendCodePoint(ch);
                } else if (ch == ':') {
                    alias = b.toString();
                    b.setLength(0);
                    // now read password chars
                    for (;;) {
                        ch = forceReadCP(br);
                        if (ch == '\n' || ch == '\r' || ch == ':') {
                            // finished
                            char[] c = new char[b.length()];
                            b.getChars(0, b.length(), c, 0);
                            final String algorithm = PasswordUtil.identifyAlgorithm(c);
                            if (algorithm == null) {
                                throw log.noAlgorithmForPassword(alias);
                            }
                            final Password pw;
                            try {
                                final PasswordSpec passwordSpec = PasswordUtil.parseCryptString(c);
                                final PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
                                pw = passwordFactory.generatePassword(passwordSpec);
                            } catch (InvalidKeySpecException e) {
                                throw log.noAlgorithmForPassword(alias);
                            }
                            map.put(alias, new PasswordEntry(pw));
                            while (ch != '\n') {
                                ch = forceReadCP(br);
                            }
                            continue outer;
                        }
                    }
                } else if (Character.isWhitespace(ch)) {
                    throw log.unexpectedWhitespaceInPasswordFile();
                } else {
                    b.appendCodePoint(ch);
                }
            }
        }
    }
}
