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

import java.io.Serializable;

/**
 * A callback used to establish the channel binding for a security mechanism which supports it.  Both the binding type
 * and data must be set, otherwise no channel binding will be established.  The channel binding type should be one of
 * the types described in <a href="http://www.iana.org/assignments/channel-binding-types/channel-binding-types.xhtml">IANA's
 * channel binding type registry</a>.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ChannelBindingCallback implements ExtendedCallback, Serializable {

    private static final long serialVersionUID = 779300207924589036L;

    /**
     * @serial The channel binding type.
     */
    private String bindingType;
    /**
     * @serial The channel binding data.
     */
    private byte[] bindingData;

    /**
     * Construct a new instance.
     */
    public ChannelBindingCallback() {
    }

    public boolean needsInformation() {
        return true;
    }

    /**
     * Get the selected channel binding type.
     *
     * @return the selected channel binding type
     */
    public String getBindingType() {
        return bindingType;
    }

    /**
     * Get the opaque channel binding data.  This data may come from the connection negotiation or from another security
     * layer.
     *
     * @return the opaque channel binding data
     */
    public byte[] getBindingData() {
        return bindingData;
    }

    /**
     * Set the selected channel binding type.  The type should be one registered with
     * <a href="http://www.iana.org/assignments/channel-binding-types/channel-binding-types.xhtml">IANA</a>.
     *
     * @param bindingType the selected channel binding type
     */
    public void setBindingType(final String bindingType) {
        this.bindingType = bindingType;
    }

    /**
     * Set the channel binding data.  This data may come from the connection negotiation or from another security layer.
     *
     * @param bindingData the channel binding data
     */
    public void setBindingData(final byte[] bindingData) {
        this.bindingData = bindingData;
    }
}
