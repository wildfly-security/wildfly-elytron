/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.wildfly.sasl.util;

import javax.security.sasl.SaslException;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface SaslState {

    /**
     * Evaluate a SASL challenge or response message.
     *
     * @param context the state context
     * @param message the message to evaluate
     * @return the reply message
     * @throws SaslException if negotiation has failed
     */
    byte[] evaluateMessage(SaslStateContext context, byte[] message) throws SaslException;

    /**
     * The SASL negotiation failure state.
     */
    SaslState FAILED = new ExceptionSaslState("SASL negotiation failed");

    /**
     * The SASL negotiation completed state.
     */
    SaslState COMPLETE = new ExceptionSaslState("SASL negotiation already complete");
}
