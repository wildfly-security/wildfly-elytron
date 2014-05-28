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

package org.wildfly.sasl.gssapi;

import org.wildfly.sasl.util.AbstractSaslFactory;


/**
 * Common factory for the GSSAPI mechanism.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class AbstractGssapiFactory extends AbstractSaslFactory {

    /**
     * The name of the ANONYMOUS SASL mechanism.
     */
    public static final String GSSAPI = "GSSAPI";

    /**
     * Construct a new instance.
     */
    protected AbstractGssapiFactory() {
        super(GSSAPI);
    }

    @Override
    protected boolean isPassCredentials() {
        /*
         * Need to double check some details on this one but as a mechanism it should be possible to delegate the clients
         * credentials to the server.
         */

        return super.isPassCredentials();
    }

    @Override
    protected boolean isActiveSusceptible() {
        return false;
    }

    @Override
    protected boolean isPlainText() {
        return false;
    }

    @Override
    protected boolean isAnonymous() {
        return false;
    }

}
