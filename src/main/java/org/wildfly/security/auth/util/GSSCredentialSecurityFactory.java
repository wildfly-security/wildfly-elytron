/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.auth.util;

import static javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag.REQUIRED;
import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security._private.ElytronMessages.log;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.wildfly.common.function.ExceptionSupplier;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.callback.FastUnsupportedCallbackException;
import org.wildfly.security.credential.GSSCredentialCredential;

/**
 * A {@link SecurityFactory} implementation for obtaining a {@link GSSCredential}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class GSSCredentialSecurityFactory implements SecurityFactory<GSSCredentialCredential> {

    private static final boolean IS_IBM = System.getProperty("java.vendor").contains("IBM");
    private static final String KRB5LoginModule = "com.sun.security.auth.module.Krb5LoginModule";
    private static final String IBMKRB5LoginModule = "com.ibm.security.auth.module.Krb5LoginModule";

    public static final Oid KERBEROS_V5;
    public static final Oid SPNEGO;

    static {
        try {
            KERBEROS_V5 = new Oid("1.2.840.113554.1.2.2");
            SPNEGO = new Oid("1.3.6.1.5.5.2");
        } catch (GSSException e) {
            throw new RuntimeException("Unable to initialise Oid", e);
        }
    }

    private final int minimumRemainingLifetime;
    private final ExceptionSupplier<GSSCredential, GeneralSecurityException> rawSupplier;

    private volatile GSSCredential cachedCredential;

    GSSCredentialSecurityFactory(final int minimumRemainingLifetime, final ExceptionSupplier<GSSCredential, GeneralSecurityException> rawSupplier) {
        this.minimumRemainingLifetime = minimumRemainingLifetime;
        this.rawSupplier = rawSupplier;
    }

    @Override
    public GSSCredentialCredential create() throws GeneralSecurityException {
        GSSCredential currentCredential = cachedCredential;
        try {
            if (currentCredential != null && currentCredential.getRemainingLifetime() >= minimumRemainingLifetime) {
                return new GSSCredentialCredential(currentCredential);
            }
            currentCredential = rawSupplier.get();
            this.cachedCredential = currentCredential;

            return new GSSCredentialCredential(currentCredential);
        } catch (GSSException e) {
            throw new GeneralSecurityException(e);
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private boolean built = false;
        private List<Oid> mechanismOids = new ArrayList<>();
        private String principal;
        private File keyTab;
        private boolean isServer;
        private int minimumRemainingLifetime;
        private int requestLifetime;
        private boolean debug;

        Builder() {
        }

        /**
         * Set the keytab file to obtain the identity.
         *
         * @param keyTab the keytab file to obtain the identity.
         * @return {@code this} to allow chaining.
         */
        public Builder setKeyTab(final File keyTab) {
            assertNotBuilt();
            this.keyTab = keyTab;

            return this;
        }

        /**
         * Set if the credential returned from the factory is representing the server side of the connection.
         *
         * @param isServer is the credential returned from the factory is representing the server side of the connection.
         * @return {@code this} to allow chaining.
         */
        public Builder setIsServer(final boolean isServer) {
            assertNotBuilt();
            this.isServer = isServer;

            return this;
        }

        /**
         * Once the factory has been called once it will cache the resulting {@link GSSCredential}, this setting
         * defines how much life it must have left in seconds for it to be re-used.
         *
         * @param minimumRemainingLifetime the time in seconds of life a {@link GSSCredential} must have to be re-used.
         * @return {@code this} to allow chaining.
         */
        public Builder setMinimumRemainingLifetime(final int minimumRemainingLifetime) {
            assertNotBuilt();
            this.minimumRemainingLifetime = minimumRemainingLifetime;

            return this;
        }

        /**
         * Set the lifetime to request newly created credentials are valid for.
         *
         * @param requestLifetime the lifetime to request newly created credentials are valid for.
         * @return {@code this} to allow chaining.
         */
        public Builder setRequestLifetime(final int requestLifetime) {
            assertNotBuilt();
            this.requestLifetime = requestLifetime;

            return this;
        }

        /**
         * Add an {@link Oid} for a mechanism the {@link GSSCredential} should be usable with.
         *
         * @param oid the {@link Oid} for the mechanism the {@link GSSCredential} should be usable with.
         * @return {@code this} to allow chaining.
         */
        public Builder addMechanismOid(final Oid oid) {
            assertNotBuilt();
            mechanismOids.add(checkNotNullParam("oid", oid));

            return this;
        }

        /**
         * Set the principal name for the initial authentication from the KeyTab.
         *
         * @param principal the principal name for the initial authentication from the KeyTab.
         * @return {@code this} to allow chaining.
         */
        public Builder setPrincipal(final String principal) {
            assertNotBuilt();
            this.principal = principal;

            return this;
        }

        /**
         * Set if debug logging should be enabled for the JAAS authentication portion of obtaining the {@link GSSCredential}
         *
         * @param debug if debug logging should be enabled for the JAAS authentication portion of obtaining the {@link GSSCredential}
         * @return {@code this} to allow chaining.
         */
        public Builder setDebug(final boolean debug) {
            assertNotBuilt();
            this.debug = debug;

            return this;
        }

        public SecurityFactory<GSSCredentialCredential> build() throws IOException {
            assertNotBuilt();
            final Configuration configuration = createConfiguration();

            built = true;
            return new GSSCredentialSecurityFactory(minimumRemainingLifetime > 0 ? minimumRemainingLifetime : 0, () -> createGSSCredential(configuration));
        }

        private GSSCredential createGSSCredential(Configuration configuration) throws GeneralSecurityException {
            final Subject subject = new Subject();

            try {
                final LoginContext lc = new LoginContext("KDC", subject, (c) -> {
                    throw new FastUnsupportedCallbackException(c[0]);
                } , configuration);
                lc.login();

                final GSSManager manager = GSSManager.getInstance();
                return Subject.doAs(subject, new PrivilegedExceptionAction<GSSCredential>() {

                    @Override
                    public GSSCredential run() throws Exception {
                        Set<KerberosPrincipal> principals = subject.getPrincipals(KerberosPrincipal.class);
                        if (principals.size() < 1) {
                            throw log.noKerberosPrincipalsFound();
                        } else if (principals.size() > 1) {
                            throw log.tooManyKerberosPrincipalsFound();
                        }
                        KerberosPrincipal principal = principals.iterator().next();
                        log.tracef("Creating GSSName for Principal '%s'" , principal);
                        GSSName name = manager.createName(principal.getName(), GSSName.NT_USER_NAME, KERBEROS_V5);

                        return manager.createCredential(name, requestLifetime, mechanismOids.toArray(new Oid[mechanismOids.size()]),
                                isServer ? GSSCredential.ACCEPT_ONLY : GSSCredential.INITIATE_ONLY);
                    }
                });

            } catch (LoginException e) {
                throw log.unableToPerformInitialLogin(e);
            } catch (PrivilegedActionException e) {
                if (e.getCause() instanceof GeneralSecurityException) {
                    throw (GeneralSecurityException) e.getCause();
                }
                throw new GeneralSecurityException(e.getCause());
            }
        }

        private Configuration createConfiguration() throws IOException {
            Map<String, Object> options = new HashMap<String, Object>();
            if (debug) {
                options.put("debug", "true");
            }
            options.put("principal", principal);

            final AppConfigurationEntry ace;
            if (IS_IBM) {
                options.put("noAddress", "true");
                options.put("credsType", isServer ? "acceptor" : "initiator");
                options.put("useKeytab", keyTab.toURI().toURL().toString());
                ace = new AppConfigurationEntry(IBMKRB5LoginModule, REQUIRED, options);
            } else {
                options.put("storeKey", "true");
                options.put("useKeyTab", "true");
                options.put("keyTab", keyTab.getAbsolutePath());
                options.put("isInitiator", isServer ? "false" : "true");

                ace = new AppConfigurationEntry(KRB5LoginModule, REQUIRED, options);
            }

            final AppConfigurationEntry[] aceArray = new AppConfigurationEntry[] { ace };

            return new Configuration() {

                @Override
                public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                    assert "KDC".equals(name);

                    return aceArray;
                }

            };
        }

        private void assertNotBuilt() {
            if (built) {
                throw log.builderAlreadyBuilt();
            }
        }


    }
}
