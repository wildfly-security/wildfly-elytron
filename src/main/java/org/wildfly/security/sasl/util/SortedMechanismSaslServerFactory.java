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
package org.wildfly.security.sasl.util;

import static org.wildfly.common.Assert.checkNotNullParam;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import javax.security.sasl.SaslServerFactory;

import org.wildfly.security.sasl.SaslMechanismSelector;

/**
 * A delegating {@link SaslServerFactory} which will sort the mechanism names using either a supplied {@link Comparator<String>}
 * or a supplied ordering of mechanism names.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SortedMechanismSaslServerFactory extends AbstractDelegatingSaslServerFactory {

    private final Comparator<String> mechanismNameComparator;
    private final SaslMechanismSelector saslMechanismSelector;

    public SortedMechanismSaslServerFactory(final SaslServerFactory delegate, final Comparator<String> mechanismNameComparator) {
        super(delegate);
        this.mechanismNameComparator = checkNotNullParam("mechanismComparator", mechanismNameComparator);
        this.saslMechanismSelector = null;
    }

    public SortedMechanismSaslServerFactory(final SaslServerFactory delegate, final String... mechanismNames) {
        super(delegate);
        checkNotNullParam("mechanismNames", mechanismNames);
        this.saslMechanismSelector = SaslMechanismSelector.NONE.addMechanisms(mechanismNames);
        this.mechanismNameComparator = null;
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> props) {
        String[] mechanismNames = super.getMechanismNames(props);
        if (mechanismNameComparator != null) {
            Arrays.sort(mechanismNames, mechanismNameComparator);
        } else if (saslMechanismSelector != null) {
            List<String> mechanismNamesList = new ArrayList<>(Arrays.asList(mechanismNames));
            mechanismNamesList = saslMechanismSelector.apply(mechanismNamesList, null);
            mechanismNames = mechanismNamesList.toArray(new String[mechanismNamesList.size()]);
        }
        return mechanismNames;
    }

}
