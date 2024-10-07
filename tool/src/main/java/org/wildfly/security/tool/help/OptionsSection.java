/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.tool.help;

import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.wildfly.security.tool.ElytronToolMessages;

/**
 * Options section of Elytron help tool
 * @author <a href="mailto:pberan@redhat.com">Petr Beran</a>
 */
public class OptionsSection extends HelpSection {

    private final String sectionTitle;
    private final String sectionHeader;
    private final Options sectionContent;

    public OptionsSection(String sectionHeader, Options options) {
        this.sectionTitle = "Options";
        this.sectionHeader = sectionHeader;
        this.sectionContent = options;
    }

    @Override
    public void printHelp() {
        formatAndPrintTitle(sectionTitle);
        if (sectionHeader != null) {
            formatAndPrintSectionContext(sectionHeader);
        }
        if (sectionContent != null) {
            HelpFormatter help = new HelpFormatter();
            help.setSyntaxPrefix("");
            help.setLeftPadding(4);
            help.setWidth(120);
            help.printHelp(ElytronToolMessages.msg.cmdHelp("", ""), sectionContent);
            printText(null);
        }
    }
}
