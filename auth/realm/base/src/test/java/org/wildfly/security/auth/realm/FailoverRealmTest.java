/*
 * Copyright 2020 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.auth.realm;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Test case testing the {@link FailoverSecurityRealm} implementation.
 *
 * @author <a href="mailto:mmazanek@redhat.com">Martin Mazanek</a>
 */
public class FailoverRealmTest {

    private static final String IDENTITY_NAME = "TestIdentity";
    private static final Principal IDENTITY_PRINCIPAL = new NamePrincipal(IDENTITY_NAME);
    private static final SecurityRealm unavailableRealm = new UnavailableRealm();
    private static final SecurityRealm workingRealm = toSecurityRealm(Attributes.EMPTY);
    private static final SecurityRealm failingRealm = new FailingRealm();

    @Test
    public void testUnavailableFailover() throws RealmUnavailableException {
        Boolean[] thrownException = {false};
        FailoverSecurityRealm failoverRealm = new FailoverSecurityRealm(unavailableRealm, workingRealm, (e) -> thrownException[0] = true);

        RealmIdentity identity = failoverRealm.getRealmIdentity(IDENTITY_PRINCIPAL);

        assertTrue(thrownException[0]);
        assertTrue(identity.exists());
    }

    @Test
    public void testFirstAvailableNoFailover() throws RealmUnavailableException {
        FailoverSecurityRealm failoverRealm = new FailoverSecurityRealm(workingRealm, failingRealm, (e) -> fail());
        RealmIdentity identity = failoverRealm.getRealmIdentity(IDENTITY_PRINCIPAL);
        assertTrue(identity.exists());
    }

    @Test
    public void testBothUnavailable() {
        Boolean[] thrownException = {false};
        try {
            FailoverSecurityRealm failoverRealm = new FailoverSecurityRealm(unavailableRealm, unavailableRealm, (e) -> thrownException[0] = true);
            failoverRealm.getRealmIdentity(IDENTITY_PRINCIPAL);
            fail();
        } catch (RealmUnavailableException e) {}
        assertTrue(thrownException[0]);
    }


    private static SecurityRealm toSecurityRealm(Attributes attributes) {
        SimpleMapBackedSecurityRealm securityRealm = new SimpleMapBackedSecurityRealm();
        if (attributes != null) {
            Map<String, SimpleRealmEntry> identityMap = new HashMap<>();
            identityMap.put(IDENTITY_NAME, new SimpleRealmEntry(Collections.emptyList(), attributes));
            securityRealm.setIdentityMap(identityMap);
        }

        return securityRealm;
    }

    private static class UnavailableRealm implements SecurityRealm {

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

    private static class FailingRealm implements SecurityRealm {

        @Override
        public RealmIdentity getRealmIdentity(Principal principal) throws RealmUnavailableException {
            fail();
            return null;
        }

        @Override
        public RealmIdentity getRealmIdentity(Evidence evidence) throws RealmUnavailableException {
            fail();
            return null;
        }

        @Override
        public RealmIdentity getRealmIdentity(Evidence evidence, Function<Principal, Principal> principalTransformer) throws RealmUnavailableException {
            fail();
            return null;
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            fail();
            return null;
        }

        @Override
        public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
            fail();
            return null;
        }
    }

}
