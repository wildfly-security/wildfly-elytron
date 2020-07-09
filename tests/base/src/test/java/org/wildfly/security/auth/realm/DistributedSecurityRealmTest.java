/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.PasswordSpec;

import java.security.Principal;
import java.security.Provider;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collections;

import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;

/**
 * Simple test case to test DistributedSecurityRealm
 *
 * @author <a href="mailto:mmazanek@redhat">Martin Mazanek</a>
 */
public class DistributedSecurityRealmTest {
    private static final Provider provider = new WildFlyElytronProvider();

    @BeforeClass
    public static void registerProvider() {
        Security.insertProviderAt(provider, 1);
    }

    @AfterClass
    public static void removeProvider() {
        Security.removeProvider(provider.getName());
    }

    SecurityRealm realm1;
    SecurityRealm realm2;
    SecurityRealm realm3;
    SecurityRealm evidenceRealm;

    char[] pass1 = "pass1".toCharArray();
    char[] pass2 = "pass2".toCharArray();
    char[] pass3 = "pass3".toCharArray();

    DistributedSecurityRealm realm;

    @Before
    public void setup() throws Exception {
        realm1 = createRealmWithIdentity("user1", createPasswordCredential(pass1));
        realm2 = createRealmWithIdentity("user2", createPasswordCredential(pass2));
        realm3 = createRealmWithIdentity("user3", createPasswordCredential(pass3));
        evidenceRealm = new SimpleEvidenceRealm();

        realm = new DistributedSecurityRealm(realm1, realm2, evidenceRealm, realm3);
    }

    @Test
    public void testNoIdentity() throws Exception {
        RealmIdentity identity = realm.getRealmIdentity(new NamePrincipal("user4"));
        Assert.assertFalse(identity.exists());
    }

    @Test
    public void testExistingIdentity1() throws Exception {
        RealmIdentity identity = realm.getRealmIdentity(new NamePrincipal("user1"));
        Assert.assertTrue(identity.exists());
        PasswordCredential credential = identity.getCredential(PasswordCredential.class);
        Assert.assertTrue(credential.verify(new PasswordGuessEvidence(pass1)));
        Assert.assertFalse(credential.verify(new PasswordGuessEvidence(pass2)));
        Assert.assertFalse(credential.verify(new PasswordGuessEvidence(pass3)));
        identity.dispose();
    }

    @Test
    public void testExistingIdentity2() throws Exception {
        RealmIdentity identity = realm.getRealmIdentity(new NamePrincipal("user2"));
        Assert.assertTrue(identity.exists());
        PasswordCredential credential = identity.getCredential(PasswordCredential.class);
        Assert.assertFalse(credential.verify(new PasswordGuessEvidence(pass1)));
        Assert.assertTrue(credential.verify(new PasswordGuessEvidence(pass2)));
        Assert.assertFalse(credential.verify(new PasswordGuessEvidence(pass3)));
        identity.dispose();
    }

    @Test
    public void testExistingIdentity3() throws Exception {
        RealmIdentity identity = realm.getRealmIdentity(new NamePrincipal("user3"));
        Assert.assertTrue(identity.exists());
        PasswordCredential credential = identity.getCredential(PasswordCredential.class);
        Assert.assertFalse(credential.verify(new PasswordGuessEvidence(pass1)));
        Assert.assertFalse(credential.verify(new PasswordGuessEvidence(pass2)));
        Assert.assertTrue(credential.verify(new PasswordGuessEvidence(pass3)));
        identity.dispose();
    }

    @Test
    public void testEvidence() throws Exception {
        RealmIdentity identity = realm.getRealmIdentity(new SimpleEvidence("evidenceUser", true));
        Assert.assertTrue(identity.exists());
        Assert.assertEquals(identity.getRealmIdentityPrincipal(), new NamePrincipal("evidenceUser"));
        identity.dispose();
    }

    @Test
    public void testBadEvidence() throws Exception {
        RealmIdentity identity = realm.getRealmIdentity(new SimpleEvidence("evidenceUser", false));
        Assert.assertFalse(identity.exists());
        identity.dispose();
    }



    private static PasswordCredential createPasswordCredential(char[] password) throws Exception {
        PasswordFactory pf = PasswordFactory.getInstance(ALGORITHM_CLEAR);
        PasswordSpec ps = new ClearPasswordSpec(password);

        return new PasswordCredential(pf.generatePassword(ps));
    }

    private static SecurityRealm createRealmWithIdentity(String identityName, Credential identityCredential) {
        SimpleMapBackedSecurityRealm realm = new SimpleMapBackedSecurityRealm();
        if (identityName != null) {
            realm.setIdentityMap(Collections.singletonMap(identityName, new SimpleRealmEntry(Collections.singletonList(identityCredential))));
        } else {
            realm.setIdentityMap(Collections.EMPTY_MAP);
        }
        return realm;
    }

    private class SimpleEvidence implements Evidence {
        private Principal principal;
        private boolean valid;

        public SimpleEvidence(String name, boolean valid) {
            this.principal = new NamePrincipal(name);
            this.valid = valid;
        }

        public boolean isValid() {
            return valid;
        }

        public Principal getPrincipal() {
            return principal;
        }
    }

    private class SimpleEvidenceRealm implements SecurityRealm {

        @Override
        public RealmIdentity getRealmIdentity(Principal principal) throws RealmUnavailableException {
            return RealmIdentity.NON_EXISTENT;
        }

        @Override
        public RealmIdentity getRealmIdentity(Evidence evidence) throws RealmUnavailableException {
            return evidence instanceof SimpleEvidence ? new SimpleEvidenceRealmIdentity((SimpleEvidence) evidence) : RealmIdentity.NON_EXISTENT;
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            return SupportLevel.UNSUPPORTED;
        }

        @Override
        public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
            return SimpleEvidence.class.equals(evidenceType) ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
        }

        private class SimpleEvidenceRealmIdentity implements RealmIdentity {

            private SimpleEvidence evidence;

            public SimpleEvidenceRealmIdentity(SimpleEvidence evidence) {
                this.evidence = evidence;
            }

            @Override
            public Principal getRealmIdentityPrincipal() {
                return evidence.getPrincipal();
            }

            @Override
            public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
                return SupportLevel.UNSUPPORTED;
            }

            @Override
            public <C extends Credential> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
                return null;
            }

            @Override
            public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
                return SimpleEvidence.class.equals(evidenceType) ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
            }

            @Override
            public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {
                return (evidence instanceof SimpleEvidence) && ((SimpleEvidence)evidence).isValid();
            }

            @Override
            public boolean exists() throws RealmUnavailableException {
                return evidence.isValid();
            }
        }
    }
}
