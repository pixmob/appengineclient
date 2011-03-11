/*
 * Copyright (C) 2011 Alexandre Roman
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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.net.URLEncoder;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.cookie.Cookie;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.DefaultHttpClient;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.accounts.AccountManagerFuture;
import android.accounts.AuthenticatorException;
import android.accounts.OperationCanceledException;
import android.content.Context;
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
            logWtf = Log.class.getMethod("wtf", new Class[] { String.class,
                    String.class, Throwable.class });
        } catch (NoSuchMethodException e) {
            logWtf = null;
        }
        LOG_WTF_METHOD = logWtf;
    }
    
    private static final String HTTP_USER_AGENT = "PixmobAppEngineClient";
    private static final String GOOGLE_ACCOUNT_TYPE = "com.google";
    private static final int HTTP_SC_AUTH_REQUIRED = 401;
    private static final int HTTP_SC_REDIRECT = 302;
    private static final int HTTP_SC_SERVER_ERROR = 500;
    private static final String TAG = "AppEngineClient";
    private final DefaultHttpClient loginClient;
    private final String appEngineHost;
    private final HttpClient delegate;
    private final AccountManager accountManager;
    private Account account;
    private String authenticationCookie;
    
    /**
     * Create a new instance. No account is set: the method
     * {@link #setAccount(String)} must be called prior to executing a request.
     * @param context used for getting services and starting intents
     * @param appEngineHost hostname where the AppEngine is hosted
     * @param delegate {@link HttpClient} instance for making HTTP requests
     */
    public AppEngineClient(final Context context, final String appEngineHost,
            final HttpClient delegate) {
        this.appEngineHost = appEngineHost;
        this.delegate = delegate;
        
        accountManager = AccountManager.get(context);
        
        loginClient = SSLEnabledHttpClient.newInstance(HTTP_USER_AGENT);
        loginClient.setCookieStore(new BasicCookieStore());
        loginClient.getParams().setBooleanParameter(
            ClientPNames.HANDLE_REDIRECTS, false);
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
    
    private String getAuthToken() throws AppEngineAuthenticationException {
        // get an authentication token from the AccountManager:
        // this call is asynchronous, as the user may not respond immediately
        final AccountManagerFuture<Bundle> futureBundle = accountManager
                .getAuthToken(account, "ah", true, null, null);
        final Bundle authBundle;
        try {
            authBundle = futureBundle.getResult();
        } catch (OperationCanceledException e) {
            throw new AppEngineAuthenticationException(
                    AUTHENTICATION_UNAVAILABLE, e);
        } catch (AuthenticatorException e) {
            throw new AppEngineAuthenticationException(
                    AUTHENTICATION_UNAVAILABLE, e);
        } catch (IOException e) {
            throw new AppEngineAuthenticationException(
                    AUTHENTICATION_UNAVAILABLE, e);
        }
        
        final String authToken = authBundle
                .getString(AccountManager.KEY_AUTHTOKEN);
        if (authToken == null) {
            // no authentication token was given: the user should give its
            // permission through an item in the notification bar
            Log.i(TAG, "Authentication permission is required");
            throw new AppEngineAuthenticationException(AUTHENTICATION_PENDING);
        }
        
        return authToken;
    }
    
    private String fetchAuthenticationCookie(String authToken)
            throws AppEngineAuthenticationException {
        final String loginUrl = "https://" + appEngineHost
                + "/_ah/login?continue=http://localhost/&auth="
                + urlEncode(authToken);
        Log.d(TAG, "Get authentication cookie from " + loginUrl);
        
        final HttpGet req = new HttpGet(loginUrl);
        final HttpResponse resp;
        try {
            resp = loginClient.execute(req);
        } catch (IOException e) {
            throw new AppEngineAuthenticationException(
                    AUTHENTICATION_UNAVAILABLE, e);
        }
        
        final int sc = resp.getStatusLine().getStatusCode();
        
        String authCookie = null;
        if (sc == HTTP_SC_REDIRECT) {
            // authentication was successful
            for (final Cookie cookie : loginClient.getCookieStore()
                    .getCookies()) {
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
            throw new AppEngineAuthenticationException(AUTHENTICATION_FAILED);
        }
        
        return authCookie;
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
    
    /**
     * Execute a request as an authenticated user. On the first request, an
     * authentication token is retrieved from the Android device. The user may
     * have to confirm the use of this authentication token. If the user has
     * previously given this permission, an authentication cookie is generated
     * for the request. If the user must give its permission or if the
     * authentication failed, an {@link AppEngineAuthenticationException} error
     * is raised. If an authentication is pending, the application should retry
     * later.
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
            authenticationCookie = fetchAuthenticationCookie(authToken);
        }
        
        HttpResponse resp = executeWithAuth(request);
        int sc = resp.getStatusLine().getStatusCode();
        if (authenticationRequired(sc)) {
            Log.d(TAG, "Invalidate authentication token");
            
            // invalidate authentication token and retry
            accountManager.invalidateAuthToken(account.type, authToken);
            
            authToken = getAuthToken();
            authenticationCookie = fetchAuthenticationCookie(authToken);
            resp = executeWithAuth(request);
            sc = resp.getStatusLine().getStatusCode();
            
            if (authenticationRequired(sc)) {
                throw new AppEngineAuthenticationException(
                        AUTHENTICATION_FAILED);
            }
        }
        
        return resp;
    }
    
    private static boolean authenticationRequired(int statusCode) {
        return statusCode == HTTP_SC_AUTH_REQUIRED
                || statusCode == HTTP_SC_SERVER_ERROR;
    }
    
    private HttpResponse executeWithAuth(HttpUriRequest request)
            throws IOException {
        request.setHeader("Cookie", "SACSID=" + authenticationCookie);
        return delegate.execute(request);
    }
    
    /**
     * Release resources associated with this client. The {@link HttpClient}
     * instance given in the constructor (which handle HTTP requests) <strong>is
     * not</strong> closed.
     */
    public void close() {
        loginClient.getConnectionManager().shutdown();
    }
}
