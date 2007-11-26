/*
 * Copyright 2007 Netflix, Inc.
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

package net.oauth.example.consumer.webapp;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.oauth.ConsumerProperties;
import net.oauth.OAuth;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthConsumer;
import net.oauth.OAuthProblemException;
import net.oauth.client.HttpClientPool;
import net.oauth.client.OAuthClient;
import net.oauth.client.OAuthHttpClient;
import net.oauth.server.OAuthServlet;
import org.apache.commons.httpclient.HttpClient;

/**
 * Utility methods for consumers that store tokens and secrets in cookies. Each
 * consumer has a name, and its accessors' credentials are stored in cookies
 * named [name].requestToken, [name].accessToken and [name].tokenSecret.
 * 
 * @author John Kristian
 */
public class CookieConsumer {

    public static final OAuthClient CLIENT = new OAuthHttpClient(
            new HttpClientPool() {
                // This trivial 'pool' simply allocates a new client every time.
                // More efficient implementations are possible.
                public HttpClient getHttpClient(URL server) {
                    return new HttpClient();
                }
            });

    private static Properties consumerProperties = null;

    private static ConsumerProperties consumers = null;

    public static OAuthConsumer getConsumer(String name, ServletContext context)
            throws IOException {
        synchronized (CookieConsumer.class) {
            if (consumers == null) {
                String resourceName = "/"
                        + CookieConsumer.class.getPackage().getName().replace(
                                ".", "/") + "/consumer.properties";
                consumerProperties = ConsumerProperties
                        .getProperties(ConsumerProperties.getResource(
                                resourceName, CookieConsumer.class
                                        .getClassLoader()));
                consumers = new ConsumerProperties(consumerProperties);
            }
        }
        if (context != null) {
            synchronized (consumerProperties) {
                String key = name + ".callbackURL";
                String value = consumerProperties.getProperty(key);
                if (value == null) {
                    // Compute the callbackURL from the servlet context.
                    URL resource = context.getResource(Callback.PATH);
                    if (resource != null) {
                        value = resource.toExternalForm();
                    } else {
                        value = Callback.PATH;
                    }
                    consumerProperties.setProperty(key, value);
                }
            }
        }
        OAuthConsumer consumer = consumers.getConsumer(name);
        return consumer;
    }

    /**
     * Get the access token and token secret for the given consumer. Get them
     * from cookies if possible; otherwise obtain them from the service
     * provider. In the latter case, throw RedirectException.
     */
    public static OAuthAccessor getAccessor(HttpServletRequest request,
            HttpServletResponse response, OAuthConsumer consumer)
            throws Exception {
        CookieMap cookies = new CookieMap(request, response);
        OAuthAccessor accessor = newAccessor(consumer, cookies);
        if (accessor.accessToken == null) {
            getAccessToken(request, cookies, accessor);
        }
        return accessor;
    }

    /**
     * Construct an accessor from cookies. The resulting accessor won't
     * necessarily have any tokens.
     */
    static OAuthAccessor newAccessor(OAuthConsumer consumer, CookieMap cookies)
            throws Exception {
        OAuthAccessor accessor = new OAuthAccessor(consumer);
        String consumerName = (String) consumer.getProperty("name");
        accessor.requestToken = cookies.get(consumerName + ".requestToken");
        accessor.accessToken = cookies.get(consumerName + ".accessToken");
        accessor.tokenSecret = cookies.get(consumerName + ".tokenSecret");
        return accessor;
    }

    /** Remove all the cookies that contain accessors' data. */
    public static void removeAccessors(CookieMap cookies) {
        List<String> names = new ArrayList<String>(cookies.keySet());
        for (String name : names) {
            if (name.endsWith(".requestToken") || name.endsWith(".accessToken")
                    || name.endsWith(".tokenSecret")) {
                cookies.remove(name);
            }
        }
    }

    /**
     * Get a fresh access token from the service provider.
     * 
     * @throws RedirectException
     *             to obtain authorization
     */
    private static void getAccessToken(HttpServletRequest request,
            CookieMap cookies, OAuthAccessor accessor) throws Exception {
        CLIENT.getRequestToken(accessor);
        String consumerName = (String) accessor.consumer.getProperty("name");
        cookies.put(consumerName + ".requestToken", accessor.requestToken);
        cookies.put(consumerName + ".tokenSecret", accessor.tokenSecret);
        String authorizationURL = accessor.consumer.serviceProvider.userAuthorizationURL;
        if (authorizationURL.startsWith("/")) {
            authorizationURL = (new URL(new URL(request.getRequestURL()
                    .toString()), request.getContextPath() + authorizationURL))
                    .toString();
        }
        URL callbackURL = new URL(new URL(request.getRequestURL().toString()),
                request.getContextPath() + Callback.PATH);
        throw new RedirectException(OAuth.addParameters(authorizationURL //
                , "oauth_token", accessor.requestToken //
                , "oauth_callback", OAuth.addParameters(callbackURL.toString() //
                        , "consumer", consumerName //
                        , "returnTo", getRequestPath(request) //
                        )));
    }

    /** Reconstruct the requested URL path, complete with query string (if any). */
    private static String getRequestPath(HttpServletRequest request)
            throws MalformedURLException {

        URL url = new URL(OAuthServlet.getRequestURL(request));
        StringBuilder path = new StringBuilder(url.getPath());
        String queryString = url.getQuery();
        if (queryString != null) {
            path.append("?").append(queryString);
        }
        return path.toString();
    }

    /**
     * Handle an exception that occurred while processing an HTTP request.
     * Depending on the exception, either send a response, redirect the client
     * or propagate an exception.
     */
    public static void handleException(Exception e, HttpServletRequest request,
            HttpServletResponse response, OAuthConsumer consumer)
            throws IOException, ServletException {
        if (e instanceof RedirectException) {
            RedirectException redirect = (RedirectException) e;
            String targetURL = redirect.getTargetURL();
            if (targetURL != null) {
                response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
                response.setHeader("Location", targetURL);
            }
        } else if (e instanceof OAuthProblemException) {
            OAuthProblemException p = (OAuthProblemException) e;
            String problem = p.getProblem();
            if (consumer != null && RECOVERABLE_PROBLEMS.contains(problem)) {
                try {
                    CookieMap cookies = new CookieMap(request, response);
                    OAuthAccessor accessor = newAccessor(consumer, cookies);
                    getAccessToken(request, cookies, accessor);
                    // getAccessToken(request, consumer,
                    // new CookieMap(request, response));
                } catch (Exception e2) {
                    handleException(e2, request, response, null);
                }
            } else {
                try {
                    StringWriter s = new StringWriter();
                    PrintWriter pw = new PrintWriter(s);
                    e.printStackTrace(pw);
                    pw.flush();
                    p.setParameter("stack trace", s.toString());
                } catch (Exception rats) {
                }
                response.setStatus(p.getHttpStatusCode());
                response.resetBuffer();
                request.setAttribute("OAuthProblemException", p);
                request.getRequestDispatcher //
                        ("/OAuthProblemException.jsp").forward(request,
                                response);
            }
        } else if (e instanceof IOException) {
            throw (IOException) e;
        } else if (e instanceof ServletException) {
            throw (ServletException) e;
        } else if (e instanceof RuntimeException) {
            throw (RuntimeException) e;
        } else {
            throw new ServletException(e);
        }
    }

    /**
     * The names of problems from which a consumer can recover by getting a
     * fresh token.
     */
    private static final Collection<String> RECOVERABLE_PROBLEMS = new HashSet<String>();
    static {
        RECOVERABLE_PROBLEMS.add("token_revoked");
        RECOVERABLE_PROBLEMS.add("token_expired");
        RECOVERABLE_PROBLEMS.add("permission_unknown");
        // In the case of permission_unknown, getting a fresh token
        // will cause the Service Provider to ask the User to decide.
    }

}
