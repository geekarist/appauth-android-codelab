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

package com.google.codelabs.appauth

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import android.support.v7.widget.AppCompatButton
import android.support.v7.widget.AppCompatTextView
import android.text.TextUtils
import android.view.View
import android.widget.Button
import android.widget.ImageView
import net.openid.appauth.AuthState
import net.openid.appauth.AuthorizationRequest
import net.openid.appauth.AuthorizationService
import net.openid.appauth.AuthorizationServiceConfiguration
import net.openid.appauth.TokenResponse
import org.json.JSONException

class MainActivity : AppCompatActivity() {

    internal var mMainApplication: MainApplication

    // state
    internal var mAuthState: AuthState? = null

    // views
    internal var mAuthorize: AppCompatButton
    internal var mMakeApiCall: AppCompatButton
    internal var mSignOut: AppCompatButton
    internal var mGivenName: AppCompatTextView
    internal var mFamilyName: AppCompatTextView
    internal var mFullName: AppCompatTextView
    internal var mProfileView: ImageView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        mMainApplication = application as MainApplication
        mAuthorize = findViewById(R.id.authorize)
        mMakeApiCall = findViewById(R.id.makeApiCall)
        mSignOut = findViewById(R.id.signOut)
        mGivenName = findViewById(R.id.givenName)
        mFamilyName = findViewById(R.id.familyName)
        mFullName = findViewById(R.id.fullName)
        mProfileView = findViewById(R.id.profileImage)

        enablePostAuthorizationFlows()

        // wire click listeners
        mAuthorize.setOnClickListener(AuthorizeListener())
    }

    override fun onStart() {
        super.onStart()
        manageIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        manageIntent(intent)
    }

    private fun manageIntent(intent: Intent?) {
        if (intent != null) {
            val action = intent.action
            when (action) {
                "TODO" -> {
                }
            }
        }
    }

    private fun enablePostAuthorizationFlows() {
        mAuthState = restoreAuthState()
        if (mAuthState != null && mAuthState!!.isAuthorized) {
            if (mMakeApiCall.visibility == View.GONE) {
                mMakeApiCall.visibility = View.VISIBLE
                mMakeApiCall.setOnClickListener(MakeApiCallListener(this,
                        mAuthState!!,
                        AuthorizationService(this)))
            }
            if (mSignOut.visibility == View.GONE) {
                mSignOut.visibility = View.VISIBLE
                mSignOut.setOnClickListener(SignOutListener(this))
            }
        } else {
            mMakeApiCall.visibility = View.GONE
            mSignOut.visibility = View.GONE
        }
    }

    /**
     * Exchanges the code, for the [TokenResponse].
     *
     * @param intent represents the [Intent] from the Custom Tabs or the System Browser.
     */
    private fun handleAuthorizationResponse(intent: Intent) {

        // code from the step 'Handle the Authorization Response' goes here.

    }

    private fun persistAuthState(authState: AuthState) {
        getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE).edit()
                .putString(AUTH_STATE,
                        authState.jsonSerializeString())
                .apply()
        enablePostAuthorizationFlows()
    }

    private fun clearAuthState() {
        getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
                .edit()
                .remove(AUTH_STATE)
                .apply()
    }

    private fun restoreAuthState(): AuthState? {
        val jsonString = getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
                .getString(AUTH_STATE, null)
        if (!TextUtils.isEmpty(jsonString)) {
            try {
                return AuthState.jsonDeserialize(jsonString!!)
            } catch (jsonException: JSONException) {
                // should never happen
            }

        }
        return null
    }

    /**
     * Kicks off the authorization flow.
     */
    class AuthorizeListener : Button.OnClickListener {

        override fun onClick(view: View) {

            val config = AuthorizationServiceConfiguration(
                    Uri.parse("https://accounts.google.com/o/oauth2/v2/auth"),
                    Uri.parse("https://www.googleapis.com/oauth2/v4/token")
            )

            val redirectUri = Uri.parse("com.google.codelabs.appauth:/oauth2callback")

            val request = AuthorizationRequest.Builder(
                    config,
                    "511828570984-fuprh0cm7665emlne3rnf9pk34kkn86s.apps.googleusercontent.com",
                    "code",
                    redirectUri
            ).setScopes("profile")
                    .build()

            val context = view.context.applicationContext
            val service = AuthorizationService(context)
            val intent = Intent("com.google.codelabs.appauth.HANDLE_AUTHORIZATION_RESPONSE")
            val pendingIntent = PendingIntent.getActivity(context, request.hashCode(), intent, 0)
            service.performAuthorizationRequest(request, pendingIntent)
        }
    }

    class SignOutListener internal constructor(private val mMainActivity: MainActivity) : Button.OnClickListener {

        override fun onClick(view: View) {
            mMainActivity.mAuthState = null
            mMainActivity.clearAuthState()
            mMainActivity.enablePostAuthorizationFlows()
        }
    }

    class MakeApiCallListener internal constructor(private val mMainActivity: MainActivity,
                                                   private val mAuthState: AuthState,
                                                   private val mAuthorizationService: AuthorizationService) : Button.OnClickListener {

        override fun onClick(view: View) {

            // code from the section 'Making API Calls' goes here

        }
    }

    companion object {

        private val SHARED_PREFERENCES_NAME = "AuthStatePreference"
        private val AUTH_STATE = "AUTH_STATE"
        private val USED_INTENT = "USED_INTENT"
    }
}
