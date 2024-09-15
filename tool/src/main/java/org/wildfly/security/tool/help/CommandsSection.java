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

import java.util.Map;

/**
 * Command section of Elytron help command
 *
 * @author <a href="mailto:pberan@redhat.com">Petr Beran</a>
 */
public class CommandsSection extends HelpSection {

    private final String sectionTitle;
    private final Map<String, String> sectionContent;

    public CommandsSection(Map<String, String> commands) {
        this.sectionTitle = "Commands";
        this.sectionContent = commands;
    }

    @Override
    public void printHelp() {
        formatAndPrintTitle(sectionTitle);
        if (sectionContent != null) {

            // Find the longest commandName
            // This is needed to make sure that all descriptions start at the same index
            int longestCommand = 0;
            for (String command : sectionContent.keySet()) {
                if (command.length() > longestCommand) {
                    longestCommand = command.length();
                }
            }
            for (Map.Entry<String, String> command : sectionContent.entrySet()) {
                formatAndPrintCommand(command.getKey(), command.getValue(), longestCommand);
            }
        }
    }

    /**
     * Formats and prints command and it's respective description
     *
     * @param commandName Command's name
     * @param commandDescription Command's description
     * @param longestCommand Length of the longest commands. Ensures that all descriptions start at the same column
     */
    protected void formatAndPrintCommand(String commandName, final CharSequence commandDescription, final int longestCommand) {
        CharSequence descriptionText = commandDescription;
        final StringBuilder stringBuilder = new StringBuilder();

        int minCommandAndDescGap = 4; // Gap between the longest commandName and its commandDescription
        int commandDescriptionStartingIndex = longestCommand + minCommandAndDescGap + leftPadding; // Starting index of all commandDescriptions in the map
        int commandDescriptionLength = lineWidth - commandDescriptionStartingIndex;

        appendGap(stringBuilder, leftPadding);
        stringBuilder.append(commandName);

        // Append a gap so that all commandDescriptions in the map start at the same index
        int realGap = commandDescriptionStartingIndex - leftPadding - commandName.length();
        appendGap(stringBuilder, realGap);

        // If the commandDescription fits one line, simply append it
        if (descriptionText.length() <= commandDescriptionLength) {
            stringBuilder.append(descriptionText);
            stringBuilder.append(System.lineSeparator());
        }
        else {
            int lineIndex = checkForWhitespaceIndex(descriptionText, commandDescriptionLength);

            // Append the commandDescription that fits on a single line and remove it from the descriptionText
            stringBuilder.append(descriptionText.subSequence(0,lineIndex));
            descriptionText = descriptionText.subSequence(lineIndex+1, descriptionText.length());
            stringBuilder.append(System.lineSeparator());

            // Appends commandDescriptions from second row onward
            while(0 < descriptionText.length()) {

                // Append a gap so that all commandDescriptions in the map start at the same index
                appendGap(stringBuilder, commandDescriptionStartingIndex);

                // If the commandDescription fits one line, simply append it and end the while loop
                if (descriptionText.length() <= commandDescriptionLength) {
                    stringBuilder.append(descriptionText);
                    stringBuilder.append(System.lineSeparator());
                    break;
                }

                lineIndex = checkForWhitespaceIndex(descriptionText, commandDescriptionLength);

                // Append the commandDescription that fits on a single line and remove it from the descriptionText
                stringBuilder.append(descriptionText.subSequence(0,lineIndex));
                descriptionText = descriptionText.subSequence(lineIndex+1, descriptionText.length());
                stringBuilder.append(System.lineSeparator());
            }
        }
        printText(stringBuilder.toString());
    }
}
