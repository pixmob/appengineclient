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
package org.pixmob.appengine.client;

import java.util.HashMap;
import java.util.Map;

import android.content.Intent;

/**
 * Error when AppEngine authentication failed.
 * @author Pixmob
 */
public class AppEngineAuthenticationException extends Exception {
    /**
     * The authentication failed for an unknown reason.
     */
    public static final int UNKNOWN_REASON = 0;
    /**
     * The user must give its permission.
     */
    public static final int AUTHENTICATION_PENDING = 1;
    /**
     * The authentication failed: the user account may not exist on the server
     * side.
     */
    public static final int AUTHENTICATION_FAILED = 2;
    /**
     * The authentication service is currently unavailable: try later.
     */
    public static final int AUTHENTICATION_UNAVAILABLE = 3;
    private static final long serialVersionUID = 1L;
    private static final Map<Integer, String> REASON_STRINGS = new HashMap<Integer, String>(4);
    private final int reason;
    private final Intent pendingAuthenticationPermissionActivity;
    
    static {
        REASON_STRINGS.put(UNKNOWN_REASON, "unknown reason");
        REASON_STRINGS.put(AUTHENTICATION_PENDING, "authentication pending");
        REASON_STRINGS.put(AUTHENTICATION_FAILED, "authentication failed");
        REASON_STRINGS.put(AUTHENTICATION_UNAVAILABLE, "authentication unavailable");
    }
    
    public AppEngineAuthenticationException(final int reason) {
        this(reason, (Intent) null);
    }
    
    public AppEngineAuthenticationException(final int reason, final Intent promptForPermissionIntent) {
        super("AppEngine authentication error (" + REASON_STRINGS.get(reason) + ")");
        this.reason = reason;
        this.pendingAuthenticationPermissionActivity = promptForPermissionIntent;
    }
    
    public AppEngineAuthenticationException(final int reason, final Throwable cause) {
        this(reason);
        initCause(cause);
    }
    
    /**
     * If the authentication requires user permission, use this intent to start
     * an activity.
     * @return user permission activity, <code>null</code> if none
     */
    public Intent getPendingAuthenticationPermissionActivity() {
        return pendingAuthenticationPermissionActivity;
    }
    
    /**
     * See why the authentication failed.
     */
    public int getReason() {
        return reason;
    }
    
    /**
     * Return <code>true</code> if the user must give its permission.
     * @return <code>true</code> if an authentication is pending
     */
    public boolean isAuthenticationPending() {
        return reason == AUTHENTICATION_PENDING;
    }
}
