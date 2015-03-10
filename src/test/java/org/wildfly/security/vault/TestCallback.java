/*
 * JBoss, Home of Professional Open Source
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
package org.wildfly.security.vault;

import org.wildfly.security.vault._private.ElytronVault;

import java.util.Map;

/**
 * Callback for test purpose.
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public class TestCallback extends VaultPasswordCallback implements ParametrizedCallback {

    /**
     * Supported suffix for parameter names.
     */
    public static final String TEST_PASSWORD_PARAMETER_NAME_SUFFIX = "test.password";

    private Map<String, ?> parameters;

    @Override
    public void initialize(Map<String, ?> parameters) {
        this.parameters = parameters;
    }

    /**
     * method which "computes" password. It can be read by {@link #getPassword()}.
     */
    public void computePassword() {
        if (parameters.get(VaultSpi.CALLBACK + "." + TEST_PASSWORD_PARAMETER_NAME_SUFFIX) != null) {
            setPassword(((String) parameters.get(VaultSpi.CALLBACK + "." + TEST_PASSWORD_PARAMETER_NAME_SUFFIX)).toCharArray());
        } else if (parameters.get(ElytronVault.KEY_PASSWORD_CALLBACK + "." + TEST_PASSWORD_PARAMETER_NAME_SUFFIX) != null) {
            setPassword(((String) parameters.get(ElytronVault.KEY_PASSWORD_CALLBACK + "." + TEST_PASSWORD_PARAMETER_NAME_SUFFIX)).toCharArray());
        }
    }

}
