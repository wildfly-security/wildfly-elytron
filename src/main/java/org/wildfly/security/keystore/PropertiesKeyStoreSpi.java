/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_MD5;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.password.spec.DigestPasswordSpec;
import org.wildfly.security.sasl.util.HexConverter;

/**
 * <p>
 * A {@link KeyStore} implementation that is backed by the {@code WildFly} users properties file.
 * </p>
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class PropertiesKeyStoreSpi extends KeyStoreSpi {

    static final char[] ESCAPE_ARRAY = new char[] { '=', '\\'};

    static final String COMMENT_PREFIX = "#";

    static final String REALM_COMMENT_PREFIX = "$REALM_NAME=";

    static final String REALM_COMMENT_SUFFIX = "$";

    static final String REALM_COMMENT_COMMENT = " This line is used by the add-user utility to identify the realm name already used in this file.";

    static final Pattern PROPERTY_PATTERN = Pattern.compile("#??([^#]*)=(([\\da-f]{2})+)$");

    private final AtomicReference<HashMap<String, EnablingPasswordEntry>> pwRef = new AtomicReference<>();
    /** The realmName as read from the properties file (or as set by the first entry added to the keystore) **/
    private final AtomicReference<String> realmName = new AtomicReference<>();
    /** Store the original file so we can write commented lines, preserving the original structure. **/
    private List<String> fileContents = new ArrayList<>();

    private final PasswordFactory passwordFactory;

    public PropertiesKeyStoreSpi() {
        try {
            passwordFactory = PasswordFactory.getInstance(ALGORITHM_DIGEST_MD5);
        } catch (NoSuchAlgorithmException e) {
            // Should be impossible to reach this as all registered by the same provider.
            throw new IllegalStateException(e);
        }
    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        final HashMap<String, EnablingPasswordEntry> map = pwRef.get();
        if (map == null) return null;
        final EnablingPasswordEntry entry = map.get(alias);
        if (entry == null) return null;
        if (password != null) {
            throw log.invalidKeyStoreEntryPassword(alias);
        }
        return entry.getPassword();
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        return null;
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        return null;
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        return null;
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        if (password != null) {
            throw new KeyStoreException(log.invalidKeyStoreEntryPassword(alias));
        }
        if (key instanceof Password) {
            engineSetEntry(alias, new EnablingPasswordEntry((Password) key), null);
        }
        throw log.invalidKeyStoreEntryType(alias, Password.class, key.getClass());
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        throw log.invalidKeyStoreEntryType(alias, Password.class, Key.class);
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        throw log.invalidKeyStoreEntryType(alias, Password.class, Certificate.class);
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        HashMap<String, EnablingPasswordEntry> map, newMap;
        do {
            map = pwRef.get();
            if (map == null || !map.containsKey(alias)) {
                return;
            }
            if (map.size() == 1) {
                newMap = null;
            } else {
                newMap = new LinkedHashMap<>(map);
                newMap.remove(alias);
            }
        } while (! pwRef.compareAndSet(map, newMap));

        // unset the realmName when the last entry was removed.
        if (newMap == null) this.realmName.set(null);
    }

    @Override
    public Enumeration<String> engineAliases() {
        final HashMap<String, EnablingPasswordEntry> map = pwRef.get();
        return Collections.enumeration(map == null ? Collections.<String>emptySet() : map.keySet());
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        final HashMap<String, EnablingPasswordEntry> map = pwRef.get();
        return map != null && map.containsKey(alias);
    }

    @Override
    public int engineSize() {
        final HashMap<String, EnablingPasswordEntry> map = pwRef.get();
        return map == null ? 0 : map.size();
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        return false;
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        return false;
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        return null;
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        final HashMap<String, EnablingPasswordEntry> map = pwRef.get();
        final String realmName = this.realmName.get();
        final List<String> fileLines = new ArrayList<>(this.fileContents);

        // we copy the current state - further changes made to the entries will not be written until store is invoked again.
        final HashMap<String, EnablingPasswordEntry> toWrite = map != null ? new HashMap<>(map) : new HashMap<>();
        final BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(stream));

        // iterate through the original file contents, then write each line applying the changes made to user entries.
        for (String line : fileLines) {
            final String trimmed = line.trim();
            if (trimmed.length() == 0) {
                writer.newLine();
            }
            else {
                final Matcher matcher = PROPERTY_PATTERN.matcher(trimmed);
                if (matcher.matches()) {
                    // this is an user entry line - write the in-memory version of the entry.
                    final String username = matcher.group(1);
                    if (toWrite.containsKey(username)) {
                        // the entry was not removed, so we write it.
                        final String escapedUsername = escapeString(username, ESCAPE_ARRAY);
                        final EnablingPasswordEntry pwdEntry = toWrite.get(username);
                        final DigestPassword digestPwd = (DigestPassword) pwdEntry.getPassword();
                        final String property = escapedUsername + "=" + HexConverter.convertToHexString(digestPwd.getDigest());
                        if (!pwdEntry.isEnabled()) {
                            writer.write(COMMENT_PREFIX);
                        }
                        toWrite.remove(username);
                        writer.write(property);
                        writer.newLine();
                    }
                } else {
                    writer.write(line);
                    writer.newLine();
                }
            }
        }

        // write any additional entries to the end of the properties file.
        for (String username : toWrite.keySet()) {
            final EnablingPasswordEntry pwdEntry = toWrite.get(username);
            final DigestPassword digestPwd = (DigestPassword) pwdEntry.getPassword();
            final String property = escapeString(username, ESCAPE_ARRAY) + "=" + HexConverter.convertToHexString(digestPwd.getDigest());
            if (!pwdEntry.isEnabled()) {
                writer.write(COMMENT_PREFIX);
            }
            writer.write(property);
            writer.newLine();
        }

        // write the realm name to the end of the properties file.
        if (realmName != null) {
            writeRealm(writer, realmName);
        }
        writer.close();
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        // load the properties file, reading the realmName and all users (enabled and disabled).
        final HashMap<String, EnablingPasswordEntry> map = new LinkedHashMap<>();
        String realmName = null;

        // TODO charset ISO_8859_1 or UTF-8?
        final BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8));
        final List<String> fileContents = new ArrayList<>();
        final List<UserEntry> userEntries = new ArrayList<>();

        String currentLine;
        while ((currentLine = reader.readLine()) != null) {
            fileContents.add(currentLine);
            final String trimmed = currentLine.trim();
            if (trimmed.startsWith(COMMENT_PREFIX) && trimmed.contains(REALM_COMMENT_PREFIX)) {
                // this is the line that contains the realm name.
                int start = trimmed.indexOf(REALM_COMMENT_PREFIX) + REALM_COMMENT_PREFIX.length();
                int end = trimmed.indexOf(REALM_COMMENT_SUFFIX, start);
                if (end > -1) {
                    realmName = trimmed.substring(start, end);
                }
                // don't add the realm block to the contents - it will always be written at the end of the file for compatibility reasons.
                fileContents.remove(currentLine);
                fileContents.remove(fileContents.size() - 1); // previous line in a realm name block is an empty comment #
                reader.readLine(); // next line in a realm name block is also an empty comment #
            } else {
                final Matcher matcher = PROPERTY_PATTERN.matcher(trimmed);
                if (matcher.matches()) {
                    String userName = matcher.group(1);
                    String hexDigest = matcher.group(2);
                    boolean commented = trimmed.startsWith(COMMENT_PREFIX);
                    // this is a line that contains an user entry (either enabled or disabled).
                    userEntries.add(new UserEntry(userName, hexDigest, commented));
                }
            }
            // ignore all the other lines (comments) - those are just added to the file contents collection.
        }

        if (userEntries.size() > 0 && realmName == null) {
            throw log.noRealmFoundInProperties();
        }

        // by now we should have read all entries and the realm. We can now build the password instances.
        for (UserEntry entry : userEntries) {
            final Password pwd;
            try {
                pwd = passwordFactory.generatePassword(
                        new DigestPasswordSpec(ALGORITHM_DIGEST_MD5, entry.username, realmName, HexConverter.convertFromHex(entry.hexDigest)));
            } catch (InvalidKeySpecException ikse) {
                throw log.noAlgorithmForPassword(entry.username);
            }
            map.put(entry.username, new EnablingPasswordEntry(pwd, !entry.isDisabled));
        }
        this.pwRef.set(map.size() > 0 ? map : null);
        this.realmName.set(realmName);
        this.fileContents = fileContents;
    }

    @Override
    public KeyStore.Entry engineGetEntry(String alias, KeyStore.ProtectionParameter protParam) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
        final HashMap<String, EnablingPasswordEntry> map = pwRef.get();
        if (map == null) return null;
        final EnablingPasswordEntry key = map.get(alias);
        if (key == null) return null;
        if (protParam != null) {
            throw log.invalidKeyStoreEntryPassword(alias);
        }
        return key;
    }

    @Override
    public void engineSetEntry(String alias, KeyStore.Entry entry, KeyStore.ProtectionParameter protParam) throws KeyStoreException {
        if (!(entry instanceof EnablingPasswordEntry)) {
            throw log.invalidKeyStoreEntryType(alias, EnablingPasswordEntry.class, entry != null ? entry.getClass() : null);
        }
        if (protParam != null) {
            throw log.keyCannotBeProtected(alias);
        }

        // validate the type of the password being added - currently only MD5 digest passwords are supported.
        final Password password = ((EnablingPasswordEntry) entry).getPassword();
        if (!(password instanceof DigestPassword)) {
            throw log.invalidPasswordType(alias, DigestPassword.class, password != null ? password.getClass() : null);
        }
        final String algorithm = password.getAlgorithm();
        if (!ALGORITHM_DIGEST_MD5.equals(algorithm)) {
            throw log.invalidAlgorithmInPasswordEntry(alias, ALGORITHM_DIGEST_MD5, algorithm);
        }

        // validate the realm in the password being added - all passwords within a file must belong to the same realm.
        final String keyStoreRealm = this.realmName.get();
        final String passwordRealm = ((DigestPassword) password).getRealm();
        if (passwordRealm == null) {
            throw log.invalidNullRealmInPasswordEntry();
        }
        else if (keyStoreRealm != null && !keyStoreRealm.equals(passwordRealm)) {
            throw log.invalidRealmNameInPasswordEntry(alias, keyStoreRealm, passwordRealm);
        }
        else if (keyStoreRealm == null) {
            // realmName is null - this must be the first entry being added to the keystore and all subsequent entries must belong to the same realm.
            if (!this.realmName.compareAndSet(keyStoreRealm, passwordRealm)) {
                // another thread has set the realm first - reload the realm name and check if it matches the password realm.
                if (!this.realmName.get().equals(passwordRealm)) {
                    throw log.invalidRealmNameInPasswordEntry(alias, this.realmName.get(), passwordRealm);
                }
            }
        }

        // set the new entry atomically.
        HashMap<String, EnablingPasswordEntry> map, newMap;
        do {
            map = pwRef.get();
            if (map == null) {
                newMap = new LinkedHashMap<>(1);
            } else {
                newMap = new LinkedHashMap<>(map);
            }
            newMap.put(alias, (EnablingPasswordEntry) entry);
        } while (! pwRef.compareAndSet(map, newMap));
    }

    @Override
    public boolean engineEntryInstanceOf(String alias, Class<? extends KeyStore.Entry> entryClass) {
        final HashMap<String, EnablingPasswordEntry> map = pwRef.get();
        return map != null && entryClass.isInstance(map.get(alias));
    }

    /**
     * Escapes the username string (uses the same logic found in WildFly's PropertiesFileLoader).
     */
    private String escapeString(String name, char[] escapeArray) {
        Arrays.sort(escapeArray);
        for(int i = 0; i < name.length(); ++i) {
            char ch = name.charAt(i);
            if (Arrays.binarySearch(escapeArray, ch) >= 0) {
                StringBuilder builder = new StringBuilder();
                builder.append(name, 0, i);
                builder.append('\\').append(ch);
                for(int j = i + 1; j < name.length(); ++j) {
                    ch = name.charAt(j);
                    if (Arrays.binarySearch(escapeArray, ch) >= 0) {
                        builder.append('\\');
                    }
                    builder.append(ch);
                }
                return builder.toString();
            }
        }
        return name;
    }

    /**
     * Writes the realm name to the properties file.
     *
     * @param bw the {@link BufferedWriter} instance to be used.
     * @param realmName the realm being written to the file.
     * @throws IOException if an error occurs while writing the realm to the properties file.
     */
    private void writeRealm(final BufferedWriter bw, final String realmName) throws IOException {
        bw.append(COMMENT_PREFIX);
        bw.newLine();
        bw.append(COMMENT_PREFIX);
        bw.append(REALM_COMMENT_PREFIX);
        bw.append(realmName);
        bw.append(REALM_COMMENT_SUFFIX);
        bw.append(REALM_COMMENT_COMMENT);
        bw.newLine();
        bw.append(COMMENT_PREFIX);
        bw.newLine();
    }

    /**
     * Class used to hold username-password entries that are read from the properties file. Commented out entries in the
     * properties file are loaded as disabled entries.
     */
    private class UserEntry {

        String username;

        String hexDigest;

        boolean isDisabled;

        UserEntry(String username, String hexDigest, boolean isDisabled) {
            this.username = username;
            this.hexDigest = hexDigest;
            this.isDisabled = isDisabled;
        }
    }
}
