// Copyright 2016 Google Inc.
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//      http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.codelabs.appauth;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.AppCompatButton;
import android.support.v7.widget.AppCompatTextView;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import net.openid.appauth.AuthState;
import net.openid.appauth.AuthorizationRequest;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.AuthorizationServiceConfiguration;
import net.openid.appauth.TokenResponse;
import org.json.JSONException;

public class MainActivity extends AppCompatActivity {
    
    private static final String SHARED_PREFERENCES_NAME = "AuthStatePreference";
    private static final String AUTH_STATE = "AUTH_STATE";
    private static final String USED_INTENT = "USED_INTENT";
    
    MainApplication mMainApplication;
    
    // state
    AuthState mAuthState;
    
    // views
    AppCompatButton mAuthorize;
    AppCompatButton mMakeApiCall;
    AppCompatButton mSignOut;
    AppCompatTextView mGivenName;
    AppCompatTextView mFamilyName;
    AppCompatTextView mFullName;
    ImageView mProfileView;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        mMainApplication = (MainApplication) getApplication();
        mAuthorize = findViewById(R.id.authorize);
        mMakeApiCall = findViewById(R.id.makeApiCall);
        mSignOut = findViewById(R.id.signOut);
        mGivenName = findViewById(R.id.givenName);
        mFamilyName = findViewById(R.id.familyName);
        mFullName = findViewById(R.id.fullName);
        mProfileView = findViewById(R.id.profileImage);
        
        enablePostAuthorizationFlows();
        
        // wire click listeners
        mAuthorize.setOnClickListener(new AuthorizeListener());
    }
    
    private void enablePostAuthorizationFlows() {
        mAuthState = restoreAuthState();
        if (mAuthState != null && mAuthState.isAuthorized()) {
            if (mMakeApiCall.getVisibility() == View.GONE) {
                mMakeApiCall.setVisibility(View.VISIBLE);
                mMakeApiCall.setOnClickListener(new MakeApiCallListener(this,
                                                                        mAuthState,
                                                                        new AuthorizationService(this)));
            }
            if (mSignOut.getVisibility() == View.GONE) {
                mSignOut.setVisibility(View.VISIBLE);
                mSignOut.setOnClickListener(new SignOutListener(this));
            }
        } else {
            mMakeApiCall.setVisibility(View.GONE);
            mSignOut.setVisibility(View.GONE);
        }
    }
    
    /**
     * Exchanges the code, for the {@link TokenResponse}.
     *
     * @param intent represents the {@link Intent} from the Custom Tabs or the System Browser.
     */
    private void handleAuthorizationResponse(@NonNull Intent intent) {
        
        // code from the step 'Handle the Authorization Response' goes here.
        
    }
    
    private void persistAuthState(@NonNull AuthState authState) {
        getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE).edit()
                                                                           .putString(AUTH_STATE,
                                                                                      authState.jsonSerializeString())
                                                                           .apply();
        enablePostAuthorizationFlows();
    }
    
    private void clearAuthState() {
        getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
            .edit()
            .remove(AUTH_STATE)
            .apply();
    }
    
    @Nullable
    private AuthState restoreAuthState() {
        String jsonString = getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
            .getString(AUTH_STATE, null);
        if (!TextUtils.isEmpty(jsonString)) {
            try {
                return AuthState.jsonDeserialize(jsonString);
            } catch (JSONException jsonException) {
                // should never happen
            }
        }
        return null;
    }
    
    /**
     * Kicks off the authorization flow.
     */
    public static class AuthorizeListener implements Button.OnClickListener {
        
        @Override
        public void onClick(View view) {
            
            AuthorizationServiceConfiguration config = new AuthorizationServiceConfiguration(
                Uri.parse("https://accounts.google.com/o/oauth2/v2/auth"),
                Uri.parse("https://www.googleapis.com/oauth2/v4/token")
            );
            
            Uri redirectUri = Uri.parse("com.google.codelabs.appauth:/oauth2callback");
            
            AuthorizationRequest request = new AuthorizationRequest.Builder(
                config,
                "511828570984-fuprh0cm7665emlne3rnf9pk34kkn86s.apps.googleusercontent.com",
                "code",
                redirectUri
            ).setScopes("profile")
             .build();
            
            Context context = view.getContext().getApplicationContext();
            AuthorizationService service = new AuthorizationService(context);
            Intent intent = new Intent("com.google.codelabs.appauth.HANDLE_AUTHORIZATION_RESPONSE");
            PendingIntent pendingIntent = PendingIntent.getActivity(context, request.hashCode(), intent, 0);
            service.performAuthorizationRequest(request, pendingIntent);
        }
    }
    
    public static class SignOutListener implements Button.OnClickListener {
        
        private final MainActivity mMainActivity;
        
        SignOutListener(@NonNull MainActivity mainActivity) {
            mMainActivity = mainActivity;
        }
        
        @Override
        public void onClick(View view) {
            mMainActivity.mAuthState = null;
            mMainActivity.clearAuthState();
            mMainActivity.enablePostAuthorizationFlows();
        }
    }
    
    public static class MakeApiCallListener implements Button.OnClickListener {
        
        private final MainActivity mMainActivity;
        private AuthState mAuthState;
        private AuthorizationService mAuthorizationService;
        
        MakeApiCallListener(@NonNull MainActivity mainActivity,
                            @NonNull AuthState authState,
                            @NonNull AuthorizationService authorizationService) {
            mMainActivity = mainActivity;
            mAuthState = authState;
            mAuthorizationService = authorizationService;
        }
        
        @Override
        public void onClick(View view) {
            
            // code from the section 'Making API Calls' goes here
            
        }
    }
}
