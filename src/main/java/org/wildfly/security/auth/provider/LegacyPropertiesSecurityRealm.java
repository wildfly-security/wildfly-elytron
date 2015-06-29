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

package org.wildfly.security.auth.provider;

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
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.spi.AuthorizationIdentity;
import org.wildfly.security.auth.spi.CredentialSupport;
import org.wildfly.security.auth.spi.RealmIdentity;
import org.wildfly.security.auth.spi.RealmUnavailableException;
import org.wildfly.security.auth.spi.SecurityRealm;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.DigestPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.DigestPasswordSpec;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.PasswordSpec;
import org.wildfly.security.util.ByteIterator;

/**
 * A {@link SecurityRealm} implementation that makes use of the legacy properties files.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class LegacyPropertiesSecurityRealm implements SecurityRealm {

    private static final String COMMENT_PREFIX = "#";
    private static final String REALM_COMMENT_PREFIX = "$REALM_NAME=";
    private static final String REALM_COMMENT_SUFFIX = "$";

    private static final Pattern HASHED_PATTERN = Pattern.compile("#??([^#]*)=(([\\da-f]{2})+)$");
    private static final Pattern PLAIN_PATTERN = Pattern.compile("#??([^#]*)=([^=]*)");

    private final boolean plainText;

    private final AtomicReference<LoadedState> loadedState = new AtomicReference<>();

    private LegacyPropertiesSecurityRealm(Builder builder) throws IOException {
        this.plainText = builder.plainText;
    }

    @Override
    public RealmIdentity createRealmIdentity(final String name) throws RealmUnavailableException {

        final LoadedState loadedState = this.loadedState.get();
        final AccountEntry accountEntry = loadedState.accounts.get(name);
        final NamePrincipal principal = new NamePrincipal(name);

        return new RealmIdentity() {

            @Override
            public Principal getPrincipal() throws RealmUnavailableException {
                return accountEntry != null ? principal : null;
            }

            @Override
            public CredentialSupport getCredentialSupport(Class<?> credentialType) throws RealmUnavailableException {
                return accountEntry != null ? LegacyPropertiesSecurityRealm.this.getCredentialSupport(credentialType) : CredentialSupport.UNSUPPORTED;
            }

            @Override
            public <C> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
                if (accountEntry == null) {
                    return null;
                }

                final PasswordFactory passwordFactory;
                final PasswordSpec passwordSpec;
                if (credentialType.isAssignableFrom(ClearPassword.class) && plainText) {
                    passwordFactory = getPasswordFactory(ALGORITHM_CLEAR);

                    passwordSpec = new ClearPasswordSpec(accountEntry.getPasswordRepresentation().toCharArray());
                } else if (credentialType.isAssignableFrom(DigestPassword.class)) {
                    passwordFactory = getPasswordFactory(ALGORITHM_DIGEST_MD5);
                    if (plainText) {
                        AlgorithmParameterSpec algorithmParameterSpec = new DigestPasswordAlgorithmSpec(ALGORITHM_DIGEST_MD5, accountEntry.getName(), loadedState.getRealmName());

                        passwordSpec = new  EncryptablePasswordSpec(accountEntry.getPasswordRepresentation().toCharArray(), algorithmParameterSpec);
                    } else {
                         byte[] hashed = ByteIterator.ofBytes(accountEntry.getPasswordRepresentation().getBytes(StandardCharsets.UTF_8)).hexDecode().drain();
                         passwordSpec = new DigestPasswordSpec(ALGORITHM_DIGEST_MD5, accountEntry.getName(), loadedState.getRealmName(), hashed);
                    }

                } else {
                    return null;
                }

                try {
                    return credentialType.cast(passwordFactory.generatePassword(passwordSpec));
                } catch (InvalidKeySpecException e) {
                    throw new IllegalStateException(e);
                }

            }

            @Override
            public boolean verifyCredential(Object credential) throws RealmUnavailableException {
                if (accountEntry == null || credential instanceof ClearPassword == false) {
                    return false;
                }

                ClearPassword testedPassword = (ClearPassword) credential;

                final PasswordFactory passwordFactory;
                final PasswordSpec passwordSpec;
                final Password actualPassword;
                if (plainText) {
                    passwordFactory = getPasswordFactory(ALGORITHM_CLEAR);
                    passwordSpec = new ClearPasswordSpec(accountEntry.getPasswordRepresentation().toCharArray());
                } else {
                    passwordFactory = getPasswordFactory(ALGORITHM_DIGEST_MD5);

                    byte[] hashed = ByteIterator.ofBytes(accountEntry.getPasswordRepresentation().getBytes(StandardCharsets.UTF_8)).hexDecode().drain();
                    passwordSpec = new DigestPasswordSpec(ALGORITHM_DIGEST_MD5, accountEntry.getName(), loadedState.getRealmName(), hashed);
                }
                try {
                    actualPassword = passwordFactory.generatePassword(passwordSpec);

                    return passwordFactory.verify(actualPassword, testedPassword.getPassword());
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
                    return null;
                }

                return new PropertiesAuthorizationIdentity(principal);
            }

        };
    }

    private PasswordFactory getPasswordFactory(final String algorithm) {
        try {
            return PasswordFactory.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }


    @Override
    public CredentialSupport getCredentialSupport(Class<?> credentialType) throws RealmUnavailableException {
        if (credentialType.isAssignableFrom(ClearPassword.class)) {
            return plainText ? CredentialSupport.FULLY_SUPPORTED : CredentialSupport.VERIFIABLE_ONLY;
        } else if (credentialType.isAssignableFrom(DigestPassword.class)) {
            return CredentialSupport.OBTAINABLE_ONLY;
        }

        return CredentialSupport.UNSUPPORTED;
    }

    private Pattern getPattern() {
        return plainText ? PLAIN_PATTERN : HASHED_PATTERN;
    }

    public void load(InputStream passwordsStream, InputStream groupsStream) throws IOException {
        Map<String, AccountEntry> accounts = new HashMap<>();
        Properties groups = new Properties();
        if (groupsStream != null) {
            try (InputStreamReader is = new InputStreamReader(groupsStream, StandardCharsets.UTF_8);) {
                groups.load(is);
            }
        }

        String realmName = null;

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(passwordsStream, StandardCharsets.UTF_8))) {

            String currentLine;
            while ((currentLine = reader.readLine()) != null) {
                final String trimmed = currentLine.trim();
                if (trimmed.startsWith(COMMENT_PREFIX) && trimmed.contains(REALM_COMMENT_PREFIX)) {
                    // this is the line that contains the realm name.
                    int start = trimmed.indexOf(REALM_COMMENT_PREFIX) + REALM_COMMENT_PREFIX.length();
                    int end = trimmed.indexOf(REALM_COMMENT_SUFFIX, start);
                    if (end > -1) {
                        realmName = trimmed.substring(start, end);
                    }
                } else {
                    final Matcher matcher = getPattern().matcher(trimmed);
                    if (matcher.matches()) {
                        String accountName = matcher.group(1);
                        String passwordRepresentation = matcher.group(2);
                        boolean commented = trimmed.startsWith(COMMENT_PREFIX);
                        if (commented == false) {
                            accounts.put(accountName, new AccountEntry(accountName, passwordRepresentation, groups.getProperty(accountName)));
                        }
                    }
                }
            }
        }

        if (realmName == null) {
            throw log.noRealmFoundInProperties();
        }

        loadedState.set(new LoadedState(accounts, realmName, System.currentTimeMillis()));
    }

    public long getLoadTime() {
        return loadedState.get().getLoadTime();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private InputStream passwordsStream;
        private InputStream groupsStream;
        private boolean plainText;

        private Builder() {
        }

        public Builder setPasswordsStream(InputStream passwordsStream) {
            this.passwordsStream = passwordsStream;

            return this;
        }

        public Builder setGroupsStream(InputStream groupsStream) {
            this.groupsStream = groupsStream;

            return this;
        }

        public Builder setPlainText(boolean plainText) {
            this.plainText = plainText;

            return this;
        }

        public LegacyPropertiesSecurityRealm build() throws IOException {
            LegacyPropertiesSecurityRealm realm = new LegacyPropertiesSecurityRealm(this);
            realm.load(passwordsStream, groupsStream);

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
        private final String groups;

        private AccountEntry(String name, String passwordRepresentation, String groups) {
            this.name = name;
            this.passwordRepresentation = passwordRepresentation;
            this.groups = groups;
        }

        public String getName() {
            return name;
        }

        public String getPasswordRepresentation() {
            return passwordRepresentation;
        }

        public String[] getGroups() {
            // TODO - We need finish off AuthenticatedRealmIdentity API
            return null;
        }
    }

    private class PropertiesAuthorizationIdentity implements AuthorizationIdentity {

        private final Principal principal;

        private PropertiesAuthorizationIdentity(Principal principal) {
            this.principal = principal;
        }

        @Override
        public Principal getPrincipal() {
            return principal;
        }
    }

}
