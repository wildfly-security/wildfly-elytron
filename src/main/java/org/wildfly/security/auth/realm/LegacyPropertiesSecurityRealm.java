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

import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_MD5;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.Provider;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import org.wildfly.common.Assert;
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
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.PasswordSpec;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.CodePointIterator;
import org.wildfly.security.util.DecodeException;

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

    private final String groupsAttribute;

    private final AtomicReference<LoadedState> loadedState = new AtomicReference<>();

    private LegacyPropertiesSecurityRealm(Builder builder) throws IOException {
        plainText = builder.plainText;
        groupsAttribute = builder.groupsAttribute;
        providers = builder.providers;
        defaultRealm = builder.defaultRealm;
    }

    @Override
    public RealmIdentity getRealmIdentity(final Principal principal) throws RealmUnavailableException {
        if (! (principal instanceof NamePrincipal)) {
            return RealmIdentity.NON_EXISTENT;
        }
        final LoadedState loadedState = this.loadedState.get();

        final AccountEntry accountEntry = loadedState.getAccounts().get(principal.getName());

        return new RealmIdentity() {

            public Principal getRealmIdentityPrincipal() {
                return principal;
            }

            @Override
            public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
                return accountEntry != null ? LegacyPropertiesSecurityRealm.this.getCredentialAcquireSupport(credentialType, algorithmName) : SupportLevel.UNSUPPORTED;
            }

            @Override
            public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
                return accountEntry != null ? LegacyPropertiesSecurityRealm.this.getEvidenceVerifySupport(evidenceType, algorithmName) : SupportLevel.UNSUPPORTED;
            }

            @Override
            public <C extends Credential> C getCredential(final Class<C> credentialType) throws RealmUnavailableException {
                return getCredential(credentialType, null);
            }

            @Override
            public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) throws RealmUnavailableException {
                if (accountEntry == null || accountEntry.getPasswordRepresentation() == null || ! PasswordCredential.class.isAssignableFrom(credentialType)) {
                    return null;
                }
                boolean clear;
                if (algorithmName == null) {
                    clear = plainText;
                } else if (ALGORITHM_CLEAR.equals(algorithmName)) {
                    clear = true;
                } else if (ALGORITHM_DIGEST_MD5.equals(algorithmName)) {
                    clear = false;
                } else {
                    return null;
                }

                final PasswordFactory passwordFactory;
                final PasswordSpec passwordSpec;

                if (clear) {
                    passwordFactory = getPasswordFactory(ALGORITHM_CLEAR);
                    passwordSpec = new ClearPasswordSpec(accountEntry.getPasswordRepresentation().toCharArray());
                } else {
                    passwordFactory = getPasswordFactory(ALGORITHM_DIGEST_MD5);
                    if (plainText) {
                        AlgorithmParameterSpec algorithmParameterSpec = new DigestPasswordAlgorithmSpec(accountEntry.getName(), loadedState.getRealmName());
                        passwordSpec = new EncryptablePasswordSpec(accountEntry.getPasswordRepresentation().toCharArray(), algorithmParameterSpec);
                    } else {
                        byte[] hashed = ByteIterator.ofBytes(accountEntry.getPasswordRepresentation().getBytes(StandardCharsets.UTF_8)).hexDecode().drain();
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
                if (accountEntry == null || accountEntry.getPasswordRepresentation() == null || !(evidence instanceof PasswordGuessEvidence)) {
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
                        byte[] hashed = ByteIterator.ofBytes(accountEntry.getPasswordRepresentation().getBytes(StandardCharsets.UTF_8)).hexDecode().drain();
                        passwordSpec = new DigestPasswordSpec(accountEntry.getName(), loadedState.getRealmName(), hashed);
                    } catch (DecodeException e) {
                        throw log.decodingHashedPasswordFromPropertiesRealmFailed(e);
                    }
                }
                try {

                    log.tracef("Attempting to authenticate account %s using LegacyPropertiesSecurityRealm.",
                        accountEntry.getName());

                    actualPassword = passwordFactory.generatePassword(passwordSpec);

                    return passwordFactory.verify(actualPassword, guess);
                } catch (InvalidKeySpecException | InvalidKeyException | IllegalStateException e) {
                    throw new IllegalStateException(e);
                }
            }

            public boolean exists() throws RealmUnavailableException {
                return accountEntry != null;
            }

            @Override
            public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
                if (accountEntry == null) {
                    return AuthorizationIdentity.EMPTY;
                }

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
    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
        Assert.checkNotNullParam("credentialType", credentialType);
        return PasswordCredential.class.isAssignableFrom(credentialType) && (algorithmName == null || algorithmName.equals(ALGORITHM_CLEAR) && plainText || algorithmName.equals(ALGORITHM_DIGEST_MD5)) ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
        return PasswordGuessEvidence.class.isAssignableFrom(evidenceType) ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
    }

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
                                    builder.appendCodePoint(it.next());
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
                if (defaultRealm != null) {
                    realmName = defaultRealm;
                } else {
                    throw log.noRealmFoundInProperties();
                }
            }
        }

        // users, which are in groups file only
        groups.stringPropertyNames().stream().filter(username -> ! accounts.containsKey(username)).forEach(username -> {
            accounts.put(username, new AccountEntry(username, null, groups.getProperty(username)));
        });

        loadedState.set(new LoadedState(accounts, realmName, System.currentTimeMillis()));
    }

    public long getLoadTime() {
        return loadedState.get().getLoadTime();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private Supplier<Provider[]> providers = Security::getProviders;
        private InputStream usersStream;
        private InputStream groupsStream;
        private String defaultRealm = null;
        private boolean plainText;
        private String groupsAttribute = "groups";

        Builder() {
        }

        /**
         * Set the supplier for {@link Provider} instanced for use bu the realm.
         *
         * @param providers the supplier for {@link Provider} instanced for use bu the realm.
         * @return this {@link Builder}
         */
        public Builder setProviders(Supplier<Provider[]> providers) {
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

    private class AccountEntry {

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
