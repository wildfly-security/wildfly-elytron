/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.credential.source;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.GSSKerberosCredential;

import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.spec.AlgorithmParameterSpec;

import static org.wildfly.security._private.ElytronMessages.log;

/**
 * A credential source which acquires a credential from local kerberos ticket cache.
 * Provides {@link org.ietf.jgss.GSSCredential} visible in {@code klist} command output etc.
 *
 * Successful obtaining from cache requires set system property {@code javax.security.auth.useSubjectCredsOnly} to {@code false}.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class LocalKerberosCredentialSource implements CredentialSource {

    private final Oid[] mechanismOids;

    LocalKerberosCredentialSource(Oid[] mechanismOids) {
        this.mechanismOids = mechanismOids;
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws IOException {
        return credentialType == GSSKerberosCredential.class ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    @Override
    public <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws IOException {
        if (credentialType != GSSKerberosCredential.class) {
            log.tracef("Unable to obtain credential of type %s from LocalKerberosCredentialSource", credentialType);
            return null;
        }

        try {
            GSSCredential gssCredential = AccessController.doPrivileged((PrivilegedExceptionAction<GSSCredential>) () -> {
                GSSManager manager = GSSManager.getInstance();
                return manager.createCredential(null, GSSCredential.DEFAULT_LIFETIME, mechanismOids, GSSCredential.INITIATE_ONLY);
            });

            log.tracef("Obtained local kerberos credential: %s", gssCredential);

            if (gssCredential == null) return null;
            return credentialType.cast(new GSSKerberosCredential(gssCredential));

        } catch (PrivilegedActionException e) {
            try {
                throw e.getCause();
            } catch (IOException | RuntimeException | Error e2) {
                throw e2;
            } catch (Throwable throwable) {
                throw new UndeclaredThrowableException(throwable);
            }
        }
    }

    /**
     * Construct a new builder instance.
     *
     * @return the new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder for a local kerberos credential source.
     */
    public static final class Builder {

        private Oid[] mechanismOids = null;

        /**
         * Set array of oid's indicating the mechanisms over which the credential is to be acquired.
         * Use {@code null} to request system specific default.
         *
         * @param mechanismOids array of mechanism oid's
         * @return this builder
         */
        public Builder setMechanismOids(Oid[] mechanismOids) {
            this.mechanismOids = mechanismOids;
            return this;
        }

        /**
         * Construct the credential source instance.
         *
         * @return the credential source
         */
        public LocalKerberosCredentialSource build() {
            return new LocalKerberosCredentialSource(mechanismOids);
        }
    }
}
