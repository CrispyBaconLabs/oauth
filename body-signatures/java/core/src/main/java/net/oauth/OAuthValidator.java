/*
 * Copyright 2008 Google, Inc.
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
package net.oauth;


/**
 * An algorithm to determine whether a message has a valid signature, a correct
 * version number, a fresh timestamp, etc.
 *
 * @author Dirk Balfanz
 * @author John Kristian
 */
public interface OAuthValidator {

    /**
     * Check that the given message from the given accessor is valid.
     * @throws OAuthProblemException the message is invalid.
     * The implementation should throw exceptions that conform to the OAuth
     * <a href="http://wiki.oauth.net/ProblemReporting">Problem Reporting extension</a>.
     */
    public void validateMessage(OAuthMessage message, OAuthAccessor accessor)
            throws Exception;

    /**
     * Check that the given message from the given accessor is valid. This
     * method will not only check the signature on the oauth parameters,
     * but also on the POST body. The POST body must NOT be of type
     * x-www-form-urlencoded. This method must only be called if the consumer
     * provided an xoauth_body_signature parameter.
     *
     * @param message The message, as received from the consumer.
     * @param accessor the accessor holding the verification keys.
     * @param contentType the content type of the POST body
     * @param signedBody the POST body whose signature is provided in the
     *        xoauth_body_signature parameter of the message.
     * @throws Exception if message or POST body didn't validate
     */
    public void validateMessageAndBody(OAuthMessage message,
            OAuthAccessor accessor, String contentType, byte[] signedBody)
            throws Exception;

}
