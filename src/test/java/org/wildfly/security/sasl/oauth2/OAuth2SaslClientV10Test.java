/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.sasl.oauth2;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class OAuth2SaslClientV10Test extends AbstractOAuth2SaslClientTest {

    @Override
    protected String getClientConfigurationFileName() {
        return "wildfly-oauth2-test-config-v1.0.xml";
    }
}
