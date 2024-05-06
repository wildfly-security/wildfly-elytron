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

import static org.wildfly.security.auth.server.ServerUtils.ELYTRON_PASSWORD_PROVIDERS;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;
import static org.wildfly.security.sasl.gssapi.TestKDC.LDAP_PORT;

import java.security.Principal;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collections;
import java.util.function.Function;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.wildfly.common.function.ExceptionSupplier;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.ldap.DirContextFactory;
import org.wildfly.security.auth.realm.ldap.LdapSecurityRealmBuilder;
import org.wildfly.security.auth.realm.ldap.SimpleDirContextFactoryBuilder;
import org.wildfly.security.auth.server.NameRewriter;
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

import javax.naming.NamingException;
import javax.naming.directory.DirContext;

/**
 * Simple test case to test DistributedSecurityRealm
 *
 * @author <a href="mailto:mmazanek@redhat">Martin Mazanek</a>
 */
public class DistributedSecurityRealmTest {
    private static final Provider provider = new WildFlyElytronProvider();

    private static final String SERVER_DN = "uid=server,dc=elytron,dc=wildfly,dc=org";
    private static final String SERVER_CREDENTIAL = "serverPassword";

    SecurityRealm realm1;
    SecurityRealm realm2;
    SecurityRealm realm3;
    SecurityRealm evidenceRealm;
    SecurityRealm unavailableRealm;
    SecurityRealm unavailableLdapRealm;

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
        unavailableRealm = new UnavailableRealm();
        unavailableLdapRealm = LdapSecurityRealmBuilder.builder()
                .setDirContextSupplier(createDirContextSupplier())
                .identityMapping()
                    .setRdnIdentifier("uid")
                    .build()
                .addDirectEvidenceVerification()
                .build();

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
        Assert.assertTrue(credential.verify(ELYTRON_PASSWORD_PROVIDERS, new PasswordGuessEvidence(pass1)));
        Assert.assertFalse(credential.verify(ELYTRON_PASSWORD_PROVIDERS, new PasswordGuessEvidence(pass2)));
        Assert.assertFalse(credential.verify(ELYTRON_PASSWORD_PROVIDERS, new PasswordGuessEvidence(pass3)));
        identity.dispose();
    }

    @Test
    public void testExistingIdentity2() throws Exception {
        RealmIdentity identity = realm.getRealmIdentity(new NamePrincipal("user2"));
        Assert.assertTrue(identity.exists());
        PasswordCredential credential = identity.getCredential(PasswordCredential.class);
        Assert.assertFalse(credential.verify(ELYTRON_PASSWORD_PROVIDERS, new PasswordGuessEvidence(pass1)));
        Assert.assertTrue(credential.verify(ELYTRON_PASSWORD_PROVIDERS, new PasswordGuessEvidence(pass2)));
        Assert.assertFalse(credential.verify(ELYTRON_PASSWORD_PROVIDERS, new PasswordGuessEvidence(pass3)));
        identity.dispose();
    }

    @Test
    public void testExistingIdentity3() throws Exception {
        RealmIdentity identity = realm.getRealmIdentity(new NamePrincipal("user3"));
        Assert.assertTrue(identity.exists());
        PasswordCredential credential = identity.getCredential(PasswordCredential.class);
        Assert.assertFalse(credential.verify(ELYTRON_PASSWORD_PROVIDERS, new PasswordGuessEvidence(pass1)));
        Assert.assertFalse(credential.verify(ELYTRON_PASSWORD_PROVIDERS, new PasswordGuessEvidence(pass2)));
        Assert.assertTrue(credential.verify(ELYTRON_PASSWORD_PROVIDERS, new PasswordGuessEvidence(pass3)));
        identity.dispose();
    }

    @Test
    public  void testVerifyEvidence() throws Exception {

        RealmIdentity identity = realm.getRealmIdentity(new NamePrincipal("user1"));
        Assert.assertTrue(identity.verifyEvidence(new PasswordGuessEvidence(pass1)));
        Assert.assertFalse(identity.verifyEvidence(new PasswordGuessEvidence(pass2)));
        Assert.assertFalse(identity.verifyEvidence(new PasswordGuessEvidence(pass3)));
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

    @Test(expected = RealmUnavailableException.class)
    public void testRealmUnavailable() throws Exception {
        realm = new DistributedSecurityRealm(realm1, realm2, unavailableLdapRealm, realm3);

        realm.getRealmIdentity(new NamePrincipal("user3"));
    }

    @Test(expected = RealmUnavailableException.class)
    public void testRealmUnavailableIgnoreFalse() throws Exception {
        boolean ignoreUnavailableRealms = false;
        realm = new DistributedSecurityRealm(ignoreUnavailableRealms, null, realm1, realm2, unavailableLdapRealm, realm3);

        realm.getRealmIdentity(new NamePrincipal("user3"));
    }

    @Test(expected = RealmUnavailableException.class)
    public void testOnlyUnavailableRealmIgnoreFalse() throws Exception {
        boolean ignoreUnavailableRealms = false;
        realm = new DistributedSecurityRealm(ignoreUnavailableRealms, null, unavailableLdapRealm);

        realm.getRealmIdentity(new NamePrincipal("user3"));
    }

    @Test
    public void testOnlyUnavailableRealmIgnoreTrueWithConsumer() throws Exception {
        int[] failedRealmIndex = {-1};

        boolean ignoreUnavailableRealms = true;
        realm = new DistributedSecurityRealm(ignoreUnavailableRealms, (index) -> failedRealmIndex[0] = index, unavailableLdapRealm);

        RealmIdentity identity = realm.getRealmIdentity(new NamePrincipal("user3"));
        Assert.assertFalse(identity.exists());
        Assert.assertEquals(0 , failedRealmIndex[0]);
        identity.dispose();
    }

    @Test
    public void testIgnoreRealmUnavailable() throws Exception {
        ignoreRealmUnavailable(unavailableLdapRealm);
    }

    @Test
    public void testIgnoreRealmIdentityUnavailable() throws Exception {
        ignoreRealmUnavailable(unavailableRealm);
    }

    @Test
    public void testIgnoreRealmUnavailableWithConsumer() throws Exception {
        ignoreRealmUnavailableWithConsumer(unavailableLdapRealm);
    }

    @Test
    public void testIgnoreRealmIdentityUnavailableWithConsumer() throws Exception {
        ignoreRealmUnavailableWithConsumer(unavailableRealm);
    }

    private void ignoreRealmUnavailable(SecurityRealm unavailableRealm) throws Exception {
        boolean ignoreUnavailableRealms = true;
        realm = new DistributedSecurityRealm(ignoreUnavailableRealms, null, realm1, realm2, unavailableRealm, realm3);

        RealmIdentity identity = realm.getRealmIdentity(new NamePrincipal("user3"));
        Assert.assertTrue(identity.exists());
        identity.dispose();
    }

    private void ignoreRealmUnavailableWithConsumer(SecurityRealm unavailableRealm) throws Exception {
        int[] failedRealmIndex = {-1};

        boolean ignoreUnavailableRealms = true;
        realm = new DistributedSecurityRealm(ignoreUnavailableRealms, (index) -> failedRealmIndex[0] = index, realm1, realm2, unavailableRealm, realm3);

        RealmIdentity identity = realm.getRealmIdentity(new NamePrincipal("user3"));
        Assert.assertTrue(identity.exists());
        Assert.assertEquals(2 , failedRealmIndex[0]);
        identity.dispose();
    }

    private static PasswordCredential createPasswordCredential(char[] password) throws Exception {
        PasswordFactory pf = PasswordFactory.getInstance(ALGORITHM_CLEAR, ELYTRON_PASSWORD_PROVIDERS);
        PasswordSpec ps = new ClearPasswordSpec(password);

        return new PasswordCredential(pf.generatePassword(ps));
    }

    private static SecurityRealm createRealmWithIdentity(String identityName, Credential identityCredential) {
        SimpleMapBackedSecurityRealm realm = new SimpleMapBackedSecurityRealm(NameRewriter.IDENTITY_REWRITER, ELYTRON_PASSWORD_PROVIDERS);
        if (identityName != null) {
            realm.setIdentityMap(Collections.singletonMap(identityName, new SimpleRealmEntry(Collections.singletonList(identityCredential))));
        } else {
            realm.setIdentityMap(Collections.EMPTY_MAP);
        }
        return realm;
    }

    private static ExceptionSupplier<DirContext, NamingException> createDirContextSupplier() {
        return () -> SimpleDirContextFactoryBuilder.builder()
                .setProviderUrl(String.format("ldap://localhost:%d/", LDAP_PORT))
                .setSecurityPrincipal(SERVER_DN)
                .setSecurityCredential(SERVER_CREDENTIAL)
                .build().obtainDirContext(DirContextFactory.ReferralMode.IGNORE);
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

    private class UnavailableRealm implements SecurityRealm {

        @Override
        public RealmIdentity getRealmIdentity(Principal principal) throws RealmUnavailableException {
            throw new RealmUnavailableException();
        }

        @Override
        public RealmIdentity getRealmIdentity(Evidence evidence) throws RealmUnavailableException {
            throw new RealmUnavailableException();
        }

        @Override
        public RealmIdentity getRealmIdentity(Evidence evidence, Function<Principal, Principal> principalTransformer) throws RealmUnavailableException {
            throw new RealmUnavailableException();
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            return SupportLevel.POSSIBLY_SUPPORTED;
        }

        @Override
        public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
            return SupportLevel.POSSIBLY_SUPPORTED;
        }
    }
}
