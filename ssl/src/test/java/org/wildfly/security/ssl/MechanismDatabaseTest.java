/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.ssl;

import org.junit.Assert;
import org.junit.Test;

public class MechanismDatabaseTest {

    @Test
    public void testBasicLoad() {
        final MechanismDatabase instance = MechanismDatabase.getInstance();
        final MechanismDatabase.Entry entry = instance.getCipherSuiteOpenSSLName("NULL-MD5");
        Assert.assertNotNull(entry);
    }

    @Test
    public void testEdhDheMapping() {
        final MechanismDatabase instance = MechanismDatabase.getInstance();
        MechanismDatabase.Entry entry;
        entry = instance.getCipherSuiteOpenSSLName("EXP-DHE-RSA-DES-CBC-SHA");
        Assert.assertNotNull(entry);
        entry = instance.getCipherSuiteOpenSSLName("DHE-DSS-CBC-SHA");
        Assert.assertNotNull(entry);
        entry = instance.getCipherSuiteOpenSSLName("EDH-DSS-DES-CBC-SHA");
        Assert.assertNotNull(entry);
        System.out.println(entry);
    }

}
