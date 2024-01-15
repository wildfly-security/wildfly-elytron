/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.wildfly.security.auth.server;

import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.event.RealmEvent;
import org.wildfly.security.auth.server.event.RealmFailedAuthenticationEvent;
import org.wildfly.security.auth.server.event.RealmSuccessfulAuthenticationEvent;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;

import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class CustomRealm implements SecurityRealm {
    public boolean wasAssertionError = false;

    // this realm does not allow acquiring credentials
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName,
                                                    AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
        return SupportLevel.UNSUPPORTED;
    }

    // this realm will be able to verify password evidences only
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName)
            throws RealmUnavailableException {
        return PasswordGuessEvidence.class.isAssignableFrom(evidenceType) ? SupportLevel.POSSIBLY_SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    public RealmIdentity getRealmIdentity(final Principal principal) throws RealmUnavailableException {

        if ("myadmin".equals(principal.getName())) { // identity "myadmin" will have password "mypassword"
            return new RealmIdentity() {
                public Principal getRealmIdentityPrincipal() {
                    return principal;
                }

                public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType,
                                                                String algorithmName, AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
                    return SupportLevel.UNSUPPORTED;
                }

                public <C extends Credential> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
                    return null;
                }

                public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) {
                    return PasswordGuessEvidence.class.isAssignableFrom(evidenceType) ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
                }

                // evidence will be accepted if it is password "mypassword"
                public boolean verifyEvidence(Evidence evidence) {
                    if (evidence instanceof PasswordGuessEvidence) {
                        PasswordGuessEvidence guess = (PasswordGuessEvidence) evidence;
                        try {
                            return Arrays.equals("mypassword".toCharArray(), guess.getGuess());

                        } finally {
                            guess.destroy();
                        }
                    }
                    return false;
                }

                public boolean exists() {
                    return true;
                }
            };
        }
        return RealmIdentity.NON_EXISTENT;
    }

    @Override
    public void handleRealmEvent(RealmEvent event) {
        try {

            if (event instanceof RealmSuccessfulAuthenticationEvent) {
                assertEquals("10.12.14.16", ((RealmSuccessfulAuthenticationEvent) event).getAuthorizationIdentity().getRuntimeAttributes().get("Source-Address").get(0));
                assertEquals("www.test-request-uri.org", ((RealmSuccessfulAuthenticationEvent) event).getAuthorizationIdentity().getRuntimeAttributes().get("Request-URI").get(0));
                assertEquals("myadmin", ((RealmSuccessfulAuthenticationEvent) event).getRealmIdentity().getRealmIdentityPrincipal().getName());
            }
            if (event instanceof RealmFailedAuthenticationEvent) {
                try {
                    assertEquals("10.12.14.16", ((RealmFailedAuthenticationEvent) event).getRealmIdentity().getAuthorizationIdentity().getRuntimeAttributes().get("Source-Address").get(0));
                    assertEquals("www.test-request-uri.org", ((RealmFailedAuthenticationEvent) event).getRealmIdentity().getAuthorizationIdentity().getRuntimeAttributes().get("Request-URI").get(0));
                    assertEquals("myadmin", ((RealmFailedAuthenticationEvent) event).getRealmIdentity().getRealmIdentityPrincipal().getName());
                } catch (RealmUnavailableException e) {
                    fail("RealmFailedAuthenticationEvent should have runtime attributes associated");
                }
            }
        } catch (AssertionError e) {
            wasAssertionError = true;
        }
    }
}

