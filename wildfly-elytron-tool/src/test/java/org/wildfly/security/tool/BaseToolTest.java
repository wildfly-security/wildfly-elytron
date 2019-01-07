/*
 * JBoss, Home of Professional Open Source
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
package org.wildfly.security.tool;

import org.junit.After;
import org.junit.Before;
import org.wildfly.security.WildFlyElytronProvider;

import java.security.Security;

/**
 * Base test class to handle necessary setup.
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public class BaseToolTest {

    private String providerName;

    /**
     * Handles JCA provider adding.
     */
    @Before
    public void addProvider() {
        final WildFlyElytronProvider provider = new WildFlyElytronProvider();
        providerName = provider.getName();
        Security.addProvider(provider);
    }

    /**
     * Handles JCA provider removing.
     */
    @After
    public void removeProvider() {
        Security.removeProvider(providerName);
    }


}
