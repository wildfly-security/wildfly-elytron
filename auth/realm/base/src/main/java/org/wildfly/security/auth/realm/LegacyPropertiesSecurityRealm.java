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

package org.wildfly.security.auth.realm;

import static org.wildfly.security.auth.realm.ElytronMessages.log;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_MD5;
import static org.wildfly.security.provider.util.ProviderUtil.INSTALLED_PROVIDERS;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import org.wildfly.common.Assert;
import org.wildfly.common.codec.DecodeException;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.DigestPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.DigestPasswordSpec;
import org.wildfly.security.password.spec.Encoding;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.PasswordSpec;

/**
 * A {@link SecurityRealm} implementation that makes use of the legacy properties files.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class LegacyPropertiesSecurityRealm implements SecurityRealm {

    private static final String COMMENT_PREFIX1 = "#";
    private static final String COMMENT_PREFIX2 = "!";
    private static final String REALM_COMMENT_PREFIX = "$REALM_NAME=";
    private static final String REALM_COMMENT_SUFFIX = "$";

    private final Supplier<Provider[]> providers;
    private final String defaultRealm;
    private final boolean plainText;
    private final Encoding hashEncoding;
    private final Charset hashCharset;

    private final String groupsAttribute;

    private final AtomicReference<LoadedState> loadedState = new AtomicReference<>();

    private LegacyPropertiesSecurityRealm(Builder builder) throws IOException {
        plainText = builder.plainText;
        groupsAttribute = builder.groupsAttribute;
        providers = builder.providers;
        defaultRealm = builder.defaultRealm;
        hashEncoding = builder.hashEncoding;
        hashCharset = builder.hashCharset;
    }

    @Override
    public RealmIdentity getRealmIdentity(final Principal principal) throws RealmUnavailableException {
        NamePrincipal namePrincipal = NamePrincipal.from(principal);
        if (namePrincipal == null) {
            log.tracef("PropertiesRealm: unsupported principal type: [%s]", principal);
            return RealmIdentity.NON_EXISTENT;
        }
        final LoadedState loadedState = this.loadedState.get();

        final AccountEntry accountEntry = loadedState.getAccounts().get(namePrincipal.getName());

        if (accountEntry == null) {
            log.tracef("PropertiesRealm: identity [%s] does not exist", namePrincipal);
            return RealmIdentity.NON_EXISTENT;
        }

        return new RealmIdentity() {

            public Principal getRealmIdentityPrincipal() {
                return namePrincipal;
            }

            @Override
            public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
                return LegacyPropertiesSecurityRealm.this.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
            }

            @Override
            public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
                return LegacyPropertiesSecurityRealm.this.getEvidenceVerifySupport(evidenceType, algorithmName);
            }

            @Override
            public <C extends Credential> C getCredential(final Class<C> credentialType) throws RealmUnavailableException {
                return getCredential(credentialType, null, null);
            }

            @Override
            public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) throws RealmUnavailableException {
                return getCredential(credentialType, algorithmName, null);
            }

            @Override
            public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
                if (accountEntry.getPasswordRepresentation() == null || LegacyPropertiesSecurityRealm.this.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec) == SupportLevel.UNSUPPORTED) {
                    log.tracef("PropertiesRealm: Unable to obtain credential for identity [%s]", namePrincipal);
                    return null;
                }

                boolean clear; // whether should be clear or digested credential returned
                if (algorithmName == null) {
                    clear = plainText;
                } else if (ALGORITHM_CLEAR.equals(algorithmName)) {
                    clear = true;
                } else if (ALGORITHM_DIGEST_MD5.equals(algorithmName)) {
                    clear = false;
                } else {
                    log.tracef("PropertiesRealm: Unable to obtain credential for identity [%s]: unsupported algorithm [%s]", namePrincipal, algorithmName);
                    return null;
                }

                final PasswordFactory passwordFactory;
                final PasswordSpec passwordSpec;

                if (clear) {
                    passwordFactory = getPasswordFactory(ALGORITHM_CLEAR);
                    passwordSpec = new ClearPasswordSpec(accountEntry.getPasswordRepresentation().toCharArray());
                } else {
                    passwordFactory = getPasswordFactory(ALGORITHM_DIGEST_MD5);
                    if (plainText) { // file contains clear passwords - needs to be digested
                        AlgorithmParameterSpec spec = parameterSpec != null ? parameterSpec : new DigestPasswordAlgorithmSpec(accountEntry.getName(), loadedState.getRealmName());
                        passwordSpec = new EncryptablePasswordSpec(accountEntry.getPasswordRepresentation().toCharArray(), spec);
                    } else { // already digested file - need to check realm name
                        if (parameterSpec != null) { // when not null, type already checked in acquire support check
                            DigestPasswordAlgorithmSpec spec = (DigestPasswordAlgorithmSpec) parameterSpec;
                            if (! loadedState.getRealmName().equals(spec.getRealm()) || ! accountEntry.getName().equals(spec.getUsername())) {
                                if (log.isTraceEnabled()) {
                                    log.tracef("PropertiesRealm: Unable to obtain credential for username [%s] (available [%s]) and realm [%s] (available [%s])",
                                            spec.getUsername(), accountEntry.getName(), spec.getRealm(), loadedState.getRealmName());
                                }
                                return null; // no digest for given username+realm
                            }
                        }
                        byte[] hashed;
                        if (hashEncoding.equals(Encoding.BASE64)) {
                            hashed = ByteIterator.ofBytes(accountEntry.getPasswordRepresentation().getBytes(hashCharset)).asUtf8String().base64Decode().drain();
                        } else {
                            // use hex by default otherwise
                            hashed = ByteIterator.ofBytes(accountEntry.getPasswordRepresentation().getBytes(hashCharset)).asUtf8String().hexDecode().drain();
                        }
                        passwordSpec = new DigestPasswordSpec(accountEntry.getName(), loadedState.getRealmName(), hashed);
                    }
                }

                try {
                    return credentialType.cast(new PasswordCredential(passwordFactory.generatePassword(passwordSpec)));
                } catch (InvalidKeySpecException e) {
                    throw new IllegalStateException(e);
                }
            }

            @Override
            public boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
                if (accountEntry.getPasswordRepresentation() == null || !(evidence instanceof PasswordGuessEvidence)) {
                    log.tracef("Unable to verify evidence for identity [%s]", namePrincipal);
                    return false;
                }
                final char[] guess = ((PasswordGuessEvidence) evidence).getGuess();

                final PasswordFactory passwordFactory;
                final PasswordSpec passwordSpec;
                final Password actualPassword;
                if (plainText) {
                    passwordFactory = getPasswordFactory(ALGORITHM_CLEAR);
                    passwordSpec = new ClearPasswordSpec(accountEntry.getPasswordRepresentation().toCharArray());
                } else {
                    passwordFactory = getPasswordFactory(ALGORITHM_DIGEST_MD5);
                    try {
                        byte[] hashed;
                        if (hashEncoding.equals(Encoding.BASE64)) {
                            hashed = ByteIterator.ofBytes(accountEntry.getPasswordRepresentation().getBytes(hashCharset)).asUtf8String().base64Decode().drain();
                        }  else {
                            // use hex by default otherwise
                            hashed = ByteIterator.ofBytes(accountEntry.getPasswordRepresentation().getBytes(hashCharset)).asUtf8String().hexDecode().drain();
                        }
                        passwordSpec = new DigestPasswordSpec(accountEntry.getName(), loadedState.getRealmName(), hashed);
                    } catch (DecodeException e) {
                        throw log.decodingHashedPasswordFromPropertiesRealmFailed(e);
                    }
                }
                try {

                    log.tracef("Attempting to authenticate account %s using LegacyPropertiesSecurityRealm.",
                        accountEntry.getName());

                    actualPassword = passwordFactory.generatePassword(passwordSpec);
                    return passwordFactory.verify(actualPassword, guess, hashCharset);
                } catch (InvalidKeySpecException | InvalidKeyException | IllegalStateException e) {
                    throw new IllegalStateException(e);
                }
            }

            public boolean exists() throws RealmUnavailableException {
                return true;
            }

            @Override
            public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
                return AuthorizationIdentity.basicIdentity(new MapAttributes(Collections.singletonMap(groupsAttribute, accountEntry.getGroups())));
            }
        };
    }

    private PasswordFactory getPasswordFactory(final String algorithm) {
        try {
            return PasswordFactory.getInstance(algorithm, providers);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
        Assert.checkNotNullParam("credentialType", credentialType);
        return PasswordCredential.class.isAssignableFrom(credentialType) &&
                (algorithmName == null || algorithmName.equals(ALGORITHM_CLEAR) && plainText || algorithmName.equals(ALGORITHM_DIGEST_MD5)) &&
                (parameterSpec == null || parameterSpec instanceof DigestPasswordAlgorithmSpec)
                ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
        return PasswordGuessEvidence.class.isAssignableFrom(evidenceType) ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    /**
     * Loads this properties security realm from the given user and groups input streams.
     *
     * @param usersStream the input stream from which the realm users are loaded
     * @param groupsStream the input stream from which the roles of realm users are loaded
     * @throws IOException if there is problem while reading the input streams or invalid content is loaded from streams
     */
    public void load(InputStream usersStream, InputStream groupsStream) throws IOException {
        Map<String, AccountEntry> accounts = new HashMap<>();
        Properties groups = new Properties();

        if (groupsStream != null) {
            try (InputStreamReader is = new InputStreamReader(groupsStream, StandardCharsets.UTF_8);) {
                groups.load(is);
            }
        }

        String realmName = null;
        if (usersStream != null) {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(usersStream, StandardCharsets.UTF_8))) {
                String currentLine;
                while ((currentLine = reader.readLine()) != null) {
                    final String trimmed = currentLine.trim();
                    if (trimmed.startsWith(COMMENT_PREFIX1) && trimmed.contains(REALM_COMMENT_PREFIX)) {
                        // this is the line that contains the realm name.
                        int start = trimmed.indexOf(REALM_COMMENT_PREFIX) + REALM_COMMENT_PREFIX.length();
                        int end = trimmed.indexOf(REALM_COMMENT_SUFFIX, start);
                        if (end > -1) {
                            realmName = trimmed.substring(start, end);
                        }
                    } else {
                        if ( ! (trimmed.startsWith(COMMENT_PREFIX1) || trimmed.startsWith(COMMENT_PREFIX2)) ) {
                            String username = null;
                            StringBuilder builder = new StringBuilder();

                            CodePointIterator it = CodePointIterator.ofString(trimmed);
                            while (it.hasNext()) {
                                int cp = it.next();
                                if (cp == '\\' && it.hasNext()) { // escape
                                    //might be regular escape of regex like characters \\t \\! or unicode \\uxxxx
                                    int marker = it.next();
                                    if(marker != 'u'){
                                        builder.appendCodePoint(marker);
                                    } else {
                                        StringBuilder hex = new StringBuilder();
                                        try{
                                            hex.appendCodePoint(it.next());
                                            hex.appendCodePoint(it.next());
                                            hex.appendCodePoint(it.next());
                                            hex.appendCodePoint(it.next());
                                            builder.appendCodePoint((char)Integer.parseInt(hex.toString(),16));
                                        } catch(NoSuchElementException nsee){
                                            throw ElytronMessages.log.invalidUnicodeSequence(hex.toString(),nsee);
                                        }
                                    }
                                } else if (username == null && (cp == '=' || cp == ':')) { // username-password delimiter
                                    username = builder.toString().trim();
                                    builder = new StringBuilder();
                                } else {
                                    builder.appendCodePoint(cp);
                                }
                            }
                            if (username != null) { // end of line and delimiter was read
                                String password = builder.toString().trim();
                                accounts.put(username, new AccountEntry(username, password, groups.getProperty(username)));
                            }
                        }
                    }
                }
            }

            if (realmName == null) {
                if (defaultRealm != null || plainText) {
                    realmName = defaultRealm;
                } else {
                    throw log.noRealmFoundInProperties();
                }
            }
        }

        // users, which are in groups file only
        for (String userName : groups.stringPropertyNames()) {
            if (accounts.containsKey(userName) == false) {
                accounts.put(userName, new AccountEntry(userName, null, groups.getProperty(userName)));
            }
        }

        loadedState.set(new LoadedState(accounts, realmName, System.currentTimeMillis()));
    }

    /**
     * Get the time when the realm was last loaded.
     *
     * @return the time when the realm was last loaded (number of milliseconds since the standard base time)
     */
    public long getLoadTime() {
        return loadedState.get().getLoadTime();
    }

    /**
     * Obtain a new {@link Builder} capable of building a {@link LegacyPropertiesSecurityRealm}.
     *
     * @return a new {@link Builder} capable of building a {@link LegacyPropertiesSecurityRealm}.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder for legacy properties security realms.
     */
    public static class Builder {

        private Supplier<Provider[]> providers = INSTALLED_PROVIDERS;
        private InputStream usersStream;
        private InputStream groupsStream;
        private String defaultRealm = null;
        private boolean plainText;
        private String groupsAttribute = "groups";
        private Encoding hashEncoding = Encoding.HEX; // set to hex by default
        private Charset hashCharset = StandardCharsets.UTF_8; // set to UTF-8 by default

        Builder() {
        }

        /**
         * Set the supplier for {@link Provider} instanced for use bu the realm.
         *
         * @param providers the supplier for {@link Provider} instanced for use bu the realm.
         * @return this {@link Builder}
         */
        public Builder setProviders(Supplier<Provider[]> providers) {
            Assert.checkNotNullParam("providers", providers);
            this.providers = providers;

            return this;
        }

        /**
         * Set the {@link InputStream} to use to load the users.
         *
         * @param usersStream the {@link InputStream} to use to load the users.
         * @return this {@link Builder}
         */
        public Builder setUsersStream(InputStream usersStream) {
            this.usersStream = usersStream;

            return this;
        }

        /**
         * Set the {@link InputStream} to use to load the group information.
         *
         * @param groupsStream the {@link InputStream} to use to load the group information.
         * @return this {@link Builder}
         */
        public Builder setGroupsStream(InputStream groupsStream) {
            this.groupsStream = groupsStream;

            return this;
        }

        /**
         * Where this realm returns an {@link AuthorizationIdentity} set the key on the Attributes that will be used to hold the
         * group membership information.
         *
         * @param groupsAttribute the key on the Attributes that will be used to hold the group membership information.
         * @return this {@link Builder}
         */
        public Builder setGroupsAttribute(final String groupsAttribute) {
            Assert.checkNotNullParam("groupsAttribute", groupsAttribute);
            this.groupsAttribute = groupsAttribute;

            return this;
        }


        /**
         * Set the default realm name to use if no realm name is discovered in the properties file.
         *
         * @param defaultRealm the default realm name if one is not discovered in the properties file.
         * @return this {@link Builder}
         */
        public Builder setDefaultRealm(String defaultRealm) {
            this.defaultRealm = defaultRealm;

            return this;
        }

        /**
         * Set format of users property file - if the passwords are stored in plain text.
         * Otherwise is HEX( MD5( username ":" realm ":" password ) ) expected.
         *
         * @param plainText if the passwords are stored in plain text.
         * @return this {@link Builder}
         */
        public Builder setPlainText(boolean plainText) {
            this.plainText = plainText;

            return this;
        }

        /**
         * Set the string format for the password in the properties file if they are not
         * stored in plain text. Set to hex by default.
         *
         * @param hashEncoding specifies the string format for the hashed password
         * @return this {@link Builder}
         */
        public Builder setHashEncoding(Encoding hashEncoding) {
            Assert.checkNotNullParam("hashEncoding", hashEncoding);
            this.hashEncoding = hashEncoding;

            return this;
        }

        /**
         * Set the character set to use when converting the password string
         * to a byte array. Set to UTF-8 by default.
         * @param hashCharset the name of the character set (must not be {@code null})
         * @return this {@link Builder}
         */
        public Builder setHashCharset(Charset hashCharset) {
            Assert.checkNotNullParam("hashCharset", hashCharset);
            this.hashCharset = hashCharset;

            return this;
        }

        /**
         * Builds the {@link LegacyPropertiesSecurityRealm}.
         * @return built {@link LegacyPropertiesSecurityRealm}
         * @throws IOException when loading of property files fails
         * @throws java.io.FileNotFoundException when property file does not exist
         * @throws RealmUnavailableException when property file of users does not contain realm name specification
         */
        public LegacyPropertiesSecurityRealm build() throws IOException {
            LegacyPropertiesSecurityRealm realm = new LegacyPropertiesSecurityRealm(this);
            realm.load(usersStream, groupsStream);

            return realm;
        }

    }

    private static class LoadedState {

        private final Map<String, AccountEntry> accounts;
        private final String realmName;
        private final long loadTime;

        private LoadedState(Map<String, AccountEntry> accounts, String realmName, long loadTime) {
            this.accounts = accounts;
            this.realmName = realmName;
            this.loadTime = loadTime;
        }

        public Map<String, AccountEntry> getAccounts() {
            return accounts;
        }

        public String getRealmName() {
            return realmName;
        }

        public long getLoadTime() {
            return loadTime;
        }

    }

    private static class AccountEntry {

        private final String name;
        private final String passwordRepresentation;
        private final Set<String> groups;

        private AccountEntry(String name, String passwordRepresentation, String groups) {
            this.name = name;
            this.passwordRepresentation = passwordRepresentation;
            this.groups = convertGroups(groups);
        }

        private Set<String> convertGroups(String groups) {
            if (groups == null) {
                return Collections.emptySet();
            }

            String[] groupArray = groups.split(",");
            Set<String> groupsSet = new HashSet<>(groupArray.length);
            for (String current : groupArray) {
                String value = current.trim();
                if (value.length() > 0) {
                    groupsSet.add(value);
                }
            }

            return Collections.unmodifiableSet(groupsSet);
        }

        public String getName() {
            return name;
        }

        public String getPasswordRepresentation() {
            return passwordRepresentation;
        }

        public Set<String> getGroups() {
            return groups;
        }
    }


}
