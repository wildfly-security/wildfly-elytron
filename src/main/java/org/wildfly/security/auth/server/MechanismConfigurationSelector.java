/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.auth.server;

/**
 * A selector to choose which {@link MechanismConfiguration} to use based on information know about the current authentication
 * attempt.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@FunctionalInterface
public interface MechanismConfigurationSelector {

    /**
     * Select the {@link MechanismConfiguration} to use for the current authentication attempt.
     *
     * @param mechanismInformation information about the current authentication attempt.
     * @return the {@link MechanismConfiguration} to use for the current authentication attempt.
     */
    MechanismConfiguration selectConfiguration(MechanismInformation mechanismInformation);

    /**
     * Create a constant {@link MechanismConfigurationSelector} which will always return the same {@link MechanismConfiguration}
     * instance.
     *
     * @param mechanismConfiguration
     * @return
     */
    static MechanismConfigurationSelector constantSelector(final MechanismConfiguration mechanismConfiguration) {
        return information -> mechanismConfiguration;
    }

}
