/*
 * Copyright (C) 2011 Pixmob (http://github.com/pixmob)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.pixmob.appengine.client;

import static com.pixmob.appengine.client.AppEngineAuthenticationException.AUTHENTICATION_FAILED;
import static com.pixmob.appengine.client.AppEngineAuthenticationException.AUTHENTICATION_PENDING;
import static com.pixmob.appengine.client.AppEngineAuthenticationException.AUTHENTICATION_UNAVAILABLE;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.net.URLEncoder;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.HttpRequestRetryHandler;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.cookie.Cookie;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.protocol.HTTP;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.accounts.AccountManagerFuture;
import android.accounts.AuthenticatorException;
import android.accounts.OperationCanceledException;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

/**
 * AppEngine HTTP client. Use this class to interact with HTTP web services
 * hosted on an AppEngine instance, where user authentication is made with a
 * Google account. Any request sent by this client will be authenticated using a
 * Google account set on the Android device. When the account is used for the
 * first time, the user is invited to give permission to use an authentication
 * token. The user does not enter his password: neither the application nor the
 * web service need to know about the user credentials.
 * @author Pixmob
 */
public class AppEngineClient {
    private static final Method LOG_WTF_METHOD;
    
    static {
        Method logWtf = null;
        try {
            logWtf = Log.class.getMethod("wtf", new Class[] { String.class, String.class,
                    Throwable.class });
        } catch (NoSuchMethodException e) {
            logWtf = null;
        }
        LOG_WTF_METHOD = logWtf;
    }
    
    private static final String HTTP_USER_AGENT = "PixmobAppEngineClient";
    private static final String GOOGLE_ACCOUNT_TYPE = "com.google";
    private static final String AUTH_COOKIE_FILE = "gae-auth_";
    private static final int HTTP_SC_AUTH_REQUIRED = 401;
    private static final int HTTP_SC_REDIRECT = 302;
    private static final String TAG = "AppEngineClient";
    private final DefaultHttpClient loginClient;
    private final String appEngineHost;
    private final HttpClient delegate;
    private final boolean delegateWasSet;
    private final AccountManager accountManager;
    private final Context context;
    private Account account;
    private String authenticationCookie;
    private String httpUserAgent;
    
    /**
     * Create a new instance, using an internal {@link HttpClient} instance.
     * This instance is managed by this class: allocated resources are released
     * with {@link #close()}.
     * @see #AppEngineClient(Context, String, HttpClient)
     */
    public AppEngineClient(final Context context, final String appEngineHost) {
        this(context, appEngineHost, null);
    }
    
    /**
     * Create a new instance. No account is set: the method
     * {@link #setAccount(String)} must be called prior to executing a request.
     * @param context used for getting services and starting intents
     * @param appEngineHost hostname where the AppEngine is hosted
     * @param delegate {@link HttpClient} instance for making HTTP requests
     */
    public AppEngineClient(final Context context, final String appEngineHost,
            final HttpClient delegate) {
        this.context = context.getApplicationContext();
        this.appEngineHost = appEngineHost;
        
        delegateWasSet = delegate != null;
        this.delegate = delegateWasSet ? delegate : SSLEnabledHttpClient
                .newInstance(HTTP_USER_AGENT);
        
        accountManager = AccountManager.get(context);
        
        loginClient = SSLEnabledHttpClient.newInstance(HTTP_USER_AGENT);
        loginClient.setCookieStore(new BasicCookieStore());
        loginClient.getParams().setBooleanParameter(ClientPNames.HANDLE_REDIRECTS, false);
        
        setRetryCount(3);
    }
    
    /**
     * Create a new instance.
     * @param context used for getting services and starting intents
     * @param appEngineHost hostname where the AppEngine is hosted
     * @param delegate {@link HttpClient} instance for making HTTP requests
     * @param accountName Google account name such as johndoe@gmail.com
     */
    public AppEngineClient(final Context context, final String appEngineHost,
            final HttpClient delegate, final String accountName) {
        this(context, appEngineHost, delegate);
        setAccount(accountName);
    }
    
    private static String urlEncode(String str) {
        String encoded = str;
        try {
            encoded = URLEncoder.encode(str, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            // unlikely to happen
            logError("UTF-8 encoding is unavailable", e);
        }
        return encoded;
    }
    
    private static void logError(String msg, Throwable e) {
        if (LOG_WTF_METHOD == null) {
            // API level < 8
            Log.e(TAG, msg, e);
        } else {
            // API level >= 8
            try {
                LOG_WTF_METHOD.invoke(null, new Object[] { TAG, msg, e });
            } catch (Exception e1) {
                // fallback
                Log.e(TAG, msg, e);
            }
        }
    }
    
    private void configureRequest(HttpUriRequest req) {
        if (httpUserAgent != null) {
            req.setHeader(HTTP.USER_AGENT, httpUserAgent);
        }
    }
    
    private String getAuthToken() throws AppEngineAuthenticationException {
        // get an authentication token from the AccountManager:
        // this call is asynchronous, as the user may not respond immediately
        final AccountManagerFuture<Bundle> futureBundle = accountManager.getAuthToken(account,
            "ah", true, null, null);
        final Bundle authBundle;
        try {
            authBundle = futureBundle.getResult();
        } catch (OperationCanceledException e) {
            throw new AppEngineAuthenticationException(AUTHENTICATION_UNAVAILABLE, e);
        } catch (AuthenticatorException e) {
            throw new AppEngineAuthenticationException(AUTHENTICATION_UNAVAILABLE, e);
        } catch (IOException e) {
            throw new AppEngineAuthenticationException(AUTHENTICATION_UNAVAILABLE, e);
        }
        
        final String authToken = authBundle.getString(AccountManager.KEY_AUTHTOKEN);
        if (authToken == null) {
            // no authentication token was given: the user should give its
            // permission through an item in the notification bar
            Log.i(TAG, "Authentication permission is required");
            
            final Intent authPermIntent = (Intent) authBundle.get(AccountManager.KEY_INTENT);
            int flags = authPermIntent.getFlags();
            flags &= ~Intent.FLAG_ACTIVITY_NEW_TASK;
            authPermIntent.setFlags(flags);
            
            throw new AppEngineAuthenticationException(AUTHENTICATION_PENDING, authPermIntent);
        }
        
        return authToken;
    }
    
    private void readAuthenticationCookie() {
        authenticationCookie = null;
        BufferedReader in = null;
        try {
            in = new BufferedReader(new InputStreamReader(context.openFileInput(AUTH_COOKIE_FILE
                    + account.name)), 128);
            authenticationCookie = in.readLine();
        } catch (IOException ignore) {
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignore) {
                }
            }
        }
    }
    
    private void writeAuthenticationCookie() {
        OutputStreamWriter out = null;
        try {
            out = new OutputStreamWriter(context.openFileOutput(AUTH_COOKIE_FILE + account.name,
                Context.MODE_PRIVATE), "UTF-8");
            
            if (authenticationCookie != null) {
                out.write(authenticationCookie);
            }
            out.write("\n");
        } catch (IOException e) {
            Log.i(TAG, "Failed to store authentication cookie", e);
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException ignore) {
                }
            }
        }
    }
    
    private String fetchAuthenticationCookie(String authToken, boolean invalidateAuthToken)
            throws AppEngineAuthenticationException {
        if (invalidateAuthToken) {
            Log.i(TAG, "Invalidate authentication token");
            
            // invalidate authentication token
            accountManager.invalidateAuthToken(account.type, authToken);
            authToken = getAuthToken();
        }
        
        final String loginUrl = "https://" + appEngineHost
                + "/_ah/login?continue=http://localhost/&auth=" + urlEncode(authToken);
        Log.d(TAG, "Get authentication cookie from " + loginUrl);
        
        final HttpGet req = new HttpGet(loginUrl);
        configureRequest(req);
        final HttpResponse resp;
        try {
            resp = safelyExecute(loginClient, req);
        } catch (IOException e) {
            throw new AppEngineAuthenticationException(AUTHENTICATION_UNAVAILABLE, e);
        }
        
        final int sc = resp.getStatusLine().getStatusCode();
        
        String authCookie = null;
        if (sc == HTTP_SC_REDIRECT) {
            // authentication was successful
            for (final Cookie cookie : loginClient.getCookieStore().getCookies()) {
                if (cookie.getName().contains("ACSID")) {
                    authCookie = cookie.getValue();
                    break;
                }
            }
            
            if (authCookie == null) {
                Log.w(TAG, "No authentication cookie was found");
            }
        } else {
            Log.i(TAG, "Authentication error: statusCode=" + sc);
        }
        
        if (authCookie == null) {
            if (!invalidateAuthToken) {
                // try again with a new authentication token
                return fetchAuthenticationCookie(authToken, true);
            } else {
                throw new AppEngineAuthenticationException(AUTHENTICATION_FAILED);
            }
        }
        
        return authCookie;
    }
    
    /**
     * Set how many times a connection is retried in case of a network error.
     * @param retryCount positive integer
     */
    public void setRetryCount(int retryCount) {
        if (retryCount < 0) {
            throw new IllegalArgumentException("Invalid retry count: " + retryCount);
        }
        
        final HttpRequestRetryHandler retryHandler = new DefaultHttpRequestRetryHandler(retryCount,
                true);
        loginClient.setHttpRequestRetryHandler(retryHandler);
        if (delegateWasSet) {
            final DefaultHttpClient client = (DefaultHttpClient) delegate;
            client.setHttpRequestRetryHandler(retryHandler);
        }
    }
    
    public void setAccount(String accountName) {
        if (accountName == null) {
            throw new IllegalArgumentException("Account name is required");
        }
        if (account != null && !account.name.equals(accountName)) {
            // reset authentication cookie since account name is different
            authenticationCookie = null;
        }
        account = new Account(accountName, GOOGLE_ACCOUNT_TYPE);
    }
    
    public void setHttpUserAgent(String httpUserAgent) {
        this.httpUserAgent = httpUserAgent;
    }
    
    /**
     * Execute a request as an authenticated user. On the first request, an
     * authentication token is retrieved from the Android device. The user may
     * have to confirm the use of this authentication token. If the user has
     * previously given this permission, an authentication cookie is generated
     * for the request. If the user must give its permission or if the
     * authentication failed, an {@link AppEngineAuthenticationException} error
     * is raised. If an authentication is pending, the application should retry
     * later.
     * <p>
     * The HTTP status code is set to <code>302</code> when the request is
     * authenticated for the first time (first call to this method).
     * </p>
     * @param request to execute
     * @return request response
     * @throws IOException if a network request could not be made
     * @throws AppEngineAuthenticationException if the authentication failed
     */
    public HttpResponse execute(HttpUriRequest request) throws IOException,
            AppEngineAuthenticationException {
        if (account == null) {
            Log.w(TAG, "No account set: cannot execute authenticated request");
            throw new AppEngineAuthenticationException(AUTHENTICATION_FAILED);
        }
        
        String authToken = getAuthToken();
        if (authenticationCookie == null) {
            readAuthenticationCookie();
            
            if (authenticationCookie == null) {
                authenticationCookie = fetchAuthenticationCookie(authToken, false);
                writeAuthenticationCookie();
            }
        }
        
        configureRequest(request);
        HttpResponse resp = executeWithAuth(request);
        int sc = resp.getStatusLine().getStatusCode();
        if (authenticationRequired(sc)) {
            closeResources(request, resp);
            authenticationCookie = fetchAuthenticationCookie(authToken, true);
            writeAuthenticationCookie();
            
            if (request instanceof HttpRequestBase) {
                try {
                    request = (HttpUriRequest) ((HttpRequestBase) request).clone();
                } catch (CloneNotSupportedException ignore) {
                }
            }
            resp = executeWithAuth(request);
            sc = resp.getStatusLine().getStatusCode();
            
            if (authenticationRequired(sc)) {
                closeResources(request, resp);
                throw new AppEngineAuthenticationException(AUTHENTICATION_FAILED);
            }
        }
        
        return resp;
    }
    
    private static boolean authenticationRequired(int statusCode) {
        return statusCode == HTTP_SC_AUTH_REQUIRED;
    }
    
    private HttpResponse executeWithAuth(HttpUriRequest request) throws IOException {
        request.setHeader("Cookie", "SACSID=" + authenticationCookie);
        return safelyExecute(delegate, request);
    }
    
    /**
     * Execute a request. If there is an error, the connection is closed.
     */
    private static HttpResponse safelyExecute(HttpClient client, HttpUriRequest request)
            throws IOException {
        HttpResponse resp = null;
        try {
            resp = client.execute(request);
        } catch (IOException e) {
            closeResources(request, resp);
            throw e;
        }
        
        return resp;
    }
    
    private static void closeResources(HttpUriRequest req, HttpResponse resp) {
        try {
            req.abort();
        } catch (UnsupportedOperationException ignore) {
        }
        final HttpEntity entity = resp != null ? resp.getEntity() : null;
        if (entity != null) {
            try {
                entity.consumeContent();
            } catch (IOException ignore) {
            }
        }
    }
    
    /**
     * Release resources associated with this client. The {@link HttpClient}
     * instance given in the constructor (which handle HTTP requests) <strong>is
     * not</strong> closed.
     */
    public void close() {
        if (!delegateWasSet) {
            // The delegate HTTP client was created by this class:
            // the allocated resources are released
            delegate.getConnectionManager().shutdown();
        }
        loginClient.getConnectionManager().shutdown();
    }
}
