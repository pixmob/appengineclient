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
package org.pixmob.appengine.client.demo;

import java.io.IOException;
import java.util.Arrays;
import java.util.Comparator;

import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.pixmob.appengine.client.AppEngineAuthenticationException;
import org.pixmob.appengine.client.AppEngineClient;
import org.pixmob.appengine.client.R;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.app.AlertDialog;
import android.app.Dialog;
import android.app.ListActivity;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.DialogInterface.OnCancelListener;
import android.content.DialogInterface.OnClickListener;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.CheckedTextView;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

/**
 * Activity showing how AppEngine Client could be used.
 * @author Pixmob
 */
public class DemoActivity extends ListActivity {
    private static final String TAG = "AppEngineClientDemo";
    private static final int AUTH_REQUEST = 1;
    private static final String APPSPOT_BASE_PREF = "appspotBase";
    private static final String APPSPOT_BASE_SET_PREF = "appspotBaseSet";
    private static final String ACCOUNT_PREF = "account";
    private static final int NO_ACCOUNT_DIALOG = 1;
    private static final int PROGRESS_DIALOG = 2;
    private static final int MODIFY_APPSPOT_BASE_DIALOG = 3;
    private SharedPreferences prefs;
    private SharedPreferences.Editor prefsEditor;
    private LoginTask loginTask;
    private AccountAdapter accountAdapter;
    private TextView appspotBaseView;
    private String appspotBase;
    private String account;
    private String defaultAppspotBase;
    
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.demo);
        
        prefs = getPreferences(MODE_PRIVATE);
        prefsEditor = prefs.edit();
        
        defaultAppspotBase = getString(R.string.default_appspot_base);
        
        appspotBaseView = (TextView) findViewById(R.id.appspot_base);
        
        loginTask = (LoginTask) getLastNonConfigurationInstance();
        if (loginTask != null) {
            loginTask.context = this;
        }
    }
    
    @Override
    public Object onRetainNonConfigurationInstance() {
        return loginTask;
    }
    
    @Override
    protected void onDestroy() {
        super.onDestroy();
        
        // clear references
        accountAdapter = null;
        appspotBaseView = null;
        
        if (loginTask != null) {
            loginTask.context = null;
            loginTask = null;
        }
    }
    
    @Override
    protected void onResume() {
        super.onResume();
        
        // restore field values
        appspotBase = prefs.getString(APPSPOT_BASE_PREF, defaultAppspotBase);
        account = prefs.getString(ACCOUNT_PREF, null);
        
        reset();
        
        if (!prefs.getBoolean(APPSPOT_BASE_SET_PREF, false)) {
            showDialog(MODIFY_APPSPOT_BASE_DIALOG);
        }
    }
    
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (AUTH_REQUEST == requestCode) {
            if (RESULT_OK == resultCode) {
                // try again since the user gave its permission
                doConnect();
            }
        }
    }
    
    @Override
    protected void onPause() {
        super.onPause();
        storeFields();
    }
    
    private void storeFields() {
        prefsEditor.putString(APPSPOT_BASE_PREF, appspotBase).putString(ACCOUNT_PREF, account);
        prefsEditor.putBoolean(APPSPOT_BASE_SET_PREF, true);
        prefsEditor.commit();
    }
    
    @Override
    protected Dialog onCreateDialog(int id) {
        if (NO_ACCOUNT_DIALOG == id) {
            final AlertDialog d = new AlertDialog.Builder(this).setTitle(R.string.error)
                    .setCancelable(false).setMessage(R.string.no_account_error).setPositiveButton(
                        R.string.quit, new OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog, int which) {
                                finish();
                            }
                        }).create();
            return d;
        }
        if (PROGRESS_DIALOG == id) {
            final ProgressDialog d = new ProgressDialog(this);
            d.setMessage(getString(R.string.connecting_to_appengine));
            d.setOnCancelListener(new OnCancelListener() {
                @Override
                public void onCancel(DialogInterface dialog) {
                    loginTask.cancel(true);
                    // release resources when the task is canceled
                    loginTask = null;
                }
            });
            return d;
        }
        if (MODIFY_APPSPOT_BASE_DIALOG == id) {
            final EditText input = new EditText(this);
            input.setSelectAllOnFocus(true);
            input.setText(prefs.getString(APPSPOT_BASE_PREF, defaultAppspotBase));
            final AlertDialog d = new AlertDialog.Builder(this).setView(input).setTitle(
                R.string.enter_appspot_instance_name).setPositiveButton(R.string.ok,
                new OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        appspotBase = trimToNull(input.getText().toString());
                        if (appspotBase == null) {
                            appspotBase = defaultAppspotBase;
                        }
                        appspotBaseView.setText(appspotBase);
                        storeFields();
                    }
                }).create();
            return d;
        }
        
        return super.onCreateDialog(id);
    }
    
    private void reset() {
        final AccountManager accountManager = AccountManager.get(this);
        final Account[] accounts = accountManager.getAccountsByType("com.google");
        if (accounts.length == 0) {
            accountAdapter = new AccountAdapter(this, new Account[0]);
            setListAdapter(accountAdapter);
            showDialog(NO_ACCOUNT_DIALOG);
        } else {
            Arrays.sort(accounts, AccountComparator.INSTANCE);
            accountAdapter = new AccountAdapter(this, accounts);
            setListAdapter(accountAdapter);
        }
        
        appspotBaseView.setText(appspotBase);
    }
    
    public void onModifyAppspotBase(View v) {
        showDialog(MODIFY_APPSPOT_BASE_DIALOG);
    }
    
    private static String trimToNull(String s) {
        final String s2 = s.trim();
        return s2.length() == 0 ? null : s2;
    }
    
    @Override
    protected void onListItemClick(ListView l, View v, int position, long id) {
        super.onListItemClick(l, v, position, id);
        account = ((Account) l.getItemAtPosition(position)).name;
        accountAdapter.notifyDataSetInvalidated();
    }
    
    public void onConnect(View view) {
        if (account == null || appspotBase == null) {
            Toast.makeText(this, R.string.missing_account, Toast.LENGTH_SHORT).show();
            return;
        }
        
        storeFields();
        doConnect();
    }
    
    private void doConnect() {
        final String appspotHost = appspotBase + ".appspot.com";
        loginTask = new LoginTask();
        loginTask.context = this;
        loginTask.execute(appspotHost, account);
    }
    
    /**
     * {@link Account} comparator for sorting accounts by their name.
     * @author Pixmob
     */
    private static class AccountComparator implements Comparator<Account> {
        public static final Comparator<Account> INSTANCE = new AccountComparator();
        
        private AccountComparator() {
        }
        
        @Override
        public int compare(Account object1, Account object2) {
            return object1.name.compareTo(object2.name);
        }
    }
    
    /**
     * {@link Account} adapter.
     * @author Pixmob
     */
    private class AccountAdapter extends ArrayAdapter<Account> {
        public AccountAdapter(final Context context, final Account[] accounts) {
            super(context, R.layout.account_row, R.id.account_name, accounts);
        }
        
        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            final LayoutInflater inflater = getLayoutInflater();
            final View row = inflater.inflate(R.layout.account_row, null);
            row.setTag(row.findViewById(R.id.account_name));
            
            final Account account = getItem(position);
            final CheckedTextView ctv = (CheckedTextView) row.getTag();
            ctv.setChecked(account.name.equals(DemoActivity.this.account));
            ctv.setText(account.name);
            
            return row;
        }
    }
    
    /**
     * Asynchronous task connecting to the AppEngine instance.
     * @author Pixmob
     */
    private static class LoginTask extends AsyncTask<String, Void, String> {
        DemoActivity context;
        private DefaultHttpClient httpClient;
        private AppEngineClient gaeClient;
        
        @Override
        protected void onPreExecute() {
            if (context != null) {
                context.showDialog(PROGRESS_DIALOG);
            }
        }
        
        @Override
        protected String doInBackground(String... params) {
            final String appspotHost = params[0];
            final String account = params[1];
            
            httpClient = new DefaultHttpClient();
            gaeClient = new AppEngineClient(context.getApplicationContext(), appspotHost,
                    httpClient, account);
            gaeClient.setHttpUserAgent("AppEngineClientDemo");
            
            final String url = "http://" + appspotHost;
            final HttpGet req = new HttpGet(url);
            
            Log.i(TAG, "Executing request: " + url);
            
            String msg = null;
            try {
                final int statusCode = gaeClient.execute(req).getStatusLine().getStatusCode();
                Log.i(TAG, "Authentication was successful");
                if (statusCode == 200) {
                    msg = context.getString(R.string.authentication_successful);
                } else {
                    msg = String.format(context.getString(R.string.status_code_result), statusCode);
                }
            } catch (IOException e) {
                Log.w(TAG, "Network error", e);
                msg = String.format(context.getString(R.string.got_error), e.getMessage());
            } catch (AppEngineAuthenticationException e) {
                if (e.isAuthenticationPending()) {
                    Log.i(TAG, "Waiting for user permission");
                    msg = null;
                    context.startActivityForResult(e.getPendingAuthenticationPermissionActivity(),
                        AUTH_REQUEST);
                } else {
                    Log.w(TAG, "Authentication error", e);
                    msg = String.format(context.getString(R.string.got_error), e.getMessage());
                }
            }
            
            return msg;
        }
        
        @Override
        protected void onCancelled() {
            super.onCancelled();
            Log.i(TAG, "Authentication cancelled");
            dispose();
        }
        
        @Override
        protected void onPostExecute(String message) {
            super.onPostExecute(message);
            dispose();
            
            if (context != null) {
                try {
                    context.dismissDialog(PROGRESS_DIALOG);
                } catch (IllegalArgumentException e) {
                    // dialog was not opened
                }
                
                if (message != null) {
                    Toast.makeText(context, message, Toast.LENGTH_LONG).show();
                }
            }
        }
        
        private void dispose() {
            if (gaeClient != null) {
                gaeClient.close();
                gaeClient = null;
            }
            if (httpClient != null) {
                httpClient.getConnectionManager().shutdown();
                httpClient = null;
            }
        }
    }
}
