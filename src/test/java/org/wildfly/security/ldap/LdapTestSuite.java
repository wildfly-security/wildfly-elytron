/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2016 Red Hat, Inc. and/or its affiliates.
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
package org.wildfly.security.ldap;

import org.junit.ClassRule;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({
        TestEnvironmentSuiteChild.class,
        AttributeMappingSuiteChild.class,
        GroupMappingSuiteChild.class,
        ModifiabilitySuiteChild.class,
        PasswordSupportSuiteChild.class,
        DirectEvidenceVerificationSuiteChild.class,
        X509EvidenceVerificationSuiteChild.class,
        PrincipalMappingSuiteChild.class,
        RoleMappingSuiteChild.class,
        KeyStoreSuiteChild.class,
        LdapSecurityRealmIdentityCacheSuiteChild.class
})
public class LdapTestSuite {
    @ClassRule
    public static DirContextFactoryRule dirContextFactory = new DirContextFactoryRule();
}
