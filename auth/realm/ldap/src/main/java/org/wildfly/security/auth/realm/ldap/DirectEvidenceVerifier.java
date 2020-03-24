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
package org.wildfly.security.auth.realm.ldap;

import static org.wildfly.security.auth.realm.ldap.ElytronMessages.log;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.Provider;
import java.util.Properties;
import java.util.function.Supplier;

import javax.naming.AuthenticationException;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;

/**
 * An {@link EvidenceVerifier} that verifies a guess by using it to connect to LDAP.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class DirectEvidenceVerifier implements EvidenceVerifier {

    private final boolean allowBlankPassword;

    DirectEvidenceVerifier(boolean allowBlankPassword) {
        this.allowBlankPassword = allowBlankPassword;
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
        return evidenceType == PasswordGuessEvidence.class ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    @Override
    public IdentityEvidenceVerifier forIdentity(final DirContext dirContext, final String distinguishedName, final String url, Attributes attributes) throws RealmUnavailableException {
        return new IdentityEvidenceVerifier() {
            @Override
            public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName, final Supplier<Provider[]> providers) throws RealmUnavailableException {
                return evidenceType == PasswordGuessEvidence.class && dirContext instanceof LdapContext ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
            }

            @Override
            public boolean verifyEvidence(Evidence evidence, final Supplier<Provider[]> providers) throws RealmUnavailableException {
                if (evidence instanceof PasswordGuessEvidence) {
                    char[] password = ((PasswordGuessEvidence) evidence).getGuess();
                    try {
                        if ( ! allowBlankPassword && password.length == 0) {
                            log.debugf("Credential direct evidence verification does not allow blank password.");
                            return false;
                        }

                        if (url != null) { // different server - create new context
                            URI uri = new URI(url);
                            String namingProviderURL = uri.getScheme() + "://" + uri.getAuthority();

                            Properties props = new Properties();
                            dirContext.getEnvironment().forEach(props::put);
                            props.put(LdapContext.PROVIDER_URL, namingProviderURL);
                            props.put(LdapContext.SECURITY_PRINCIPAL, distinguishedName);
                            props.put(LdapContext.SECURITY_CREDENTIALS, password);

                            LdapContext userContext;
                            if (dirContext instanceof DelegatingLdapContext) {
                                userContext = ((DelegatingLdapContext) dirContext).newInitialLdapContext(props, null);
                            } else {
                                userContext = new InitialLdapContext(props, null);
                            }
                            userContext.close();
                        } else { // the same context - copy context
                            LdapContext userContext = ((LdapContext) dirContext).newInstance(null);
                            userContext.addToEnvironment(LdapContext.SECURITY_PRINCIPAL, distinguishedName);
                            userContext.addToEnvironment(LdapContext.SECURITY_CREDENTIALS, password);
                            userContext.reconnect(null);
                            userContext.close();
                        }
                        return true;
                    } catch (AuthenticationException e) {
                        log.debugf(e, "Credential direct evidence verification failed. DN: [%s]", distinguishedName);
                    } catch (NamingException | URISyntaxException e) {
                        throw log.directLdapVerificationFailed(distinguishedName, url, e);
                    } finally {
                        ((PasswordGuessEvidence) evidence).destroy();
                    }
                }

                return false;
            }

        };
    }
}
