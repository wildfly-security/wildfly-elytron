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

package org.wildfly.security.auth.callback;

import javax.security.auth.callback.ChoiceCallback;

/**
 * A variation on {@code ChoiceCallback} which supports the extended callback interface.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class ExtendedChoiceCallback extends ChoiceCallback implements ExtendedCallback {

    private static final long serialVersionUID = 2222777746412093737L;

    /**
     * @serial A flag indicating whether the callback is optional.
     */
    private final boolean optional;

    /**
     * Construct a new instance.
     *
     * @param prompt the text prompt (must not be {@code null})
     * @param choices the choices (must not be {@code null})
     * @param defaultChoice the default choice as an index into the {@code choices} array
     * @param multipleSelectionsAllowed {@code true} if multiple selections are allowed
     * @param optional {@code true} if the support for the callback is optional
     */
    public ExtendedChoiceCallback(final String prompt, final String[] choices, final int defaultChoice, final boolean multipleSelectionsAllowed, final boolean optional) {
        super(prompt, choices, defaultChoice, multipleSelectionsAllowed);
        this.optional = optional;
    }

    public boolean isOptional() {
        return optional;
    }

    public boolean needsInformation() {
        return true;
    }
}
