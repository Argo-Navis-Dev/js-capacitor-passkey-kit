package com.argonavisdev.jscapacitorpasskeykit.plugins.passkey

import android.app.Activity
import android.util.Log
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialInterruptedException
import androidx.credentials.exceptions.CreateCredentialProviderConfigurationException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.CreateCredentialUnsupportedException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialInterruptedException
import androidx.credentials.exceptions.GetCredentialProviderConfigurationException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialUnsupportedException
import androidx.credentials.exceptions.NoCredentialException
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import androidx.credentials.exceptions.publickeycredential.GetPublicKeyCredentialDomException
import com.getcapacitor.JSObject
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.CapacitorPlugin
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.json.JSONObject

@CapacitorPlugin(name = "PasskeyPlugin")
class PasskeyPlugin : Plugin() {

    private val mainScope = CoroutineScope(Dispatchers.Main)

    object ErrorCodes {
        const val UNKNOWN = "UNKNOWN_ERROR"
        const val CANCELLED = "CANCELLED"
        const val DOM = "DOM_ERROR"
        const val NO_ACTIVITY = "NO_ACTIVITY"
        const val UNSUPPORTED = "UNSUPPORTED_ERROR"
        const val PROVIDER_CONFIG_ERROR = "PROVIDER_CONFIG_ERROR"
        const val INTERRUPTED = "INTERRUPTED"
        const val NO_CREDENTIAL = "NO_CREDENTIAL"
    }

    @PluginMethod
    fun createPasskey(call: PluginCall) {
        Log.d("PasskeyPlugin", "CreatePasskey method has been called with parameters: ${call.data}")
        val publicKey = call.getObject("publicKey")

        if (publicKey == null) {
            Log.e("PasskeyPlugin", "Passkey registration failed, publicKey is null in request!")
            handlePluginError(call, message = "PublicKey is null in request!")
            return
        }

        val credentialManager = CredentialManager.Companion.create(context)
        val createPublicKeyCredentialRequest =
            CreatePublicKeyCredentialRequest(publicKey.toString())
        mainScope.launch {
            try {
                val activity: Activity? = activity
                if (activity == null) {
                    handlePluginError(call, message = "No activity found to handle passkey registration!")
                    return@launch
                }
                val credentialResult = activity.let {
                    credentialManager.createCredential(
                        it,
                        createPublicKeyCredentialRequest
                    )
                }
                val registrationResponseStr =
                    credentialResult.data.getString("androidx.credentials.BUNDLE_KEY_REGISTRATION_RESPONSE_JSON")
                Log.d("PasskeyPlugin", "Passkey registration native response: $registrationResponseStr")
                if (!registrationResponseStr.isNullOrEmpty()) {
                    //Convert the response data to a JSONObject
                    val registrationResponseJson = JSONObject(registrationResponseStr)

                    val responseField = registrationResponseJson.optJSONObject("response")
                    if (responseField == null) {
                        handlePluginError(call, message = "Malformed response: missing 'response' field")
                        return@launch
                    }
                    val passkeyResponse = JSObject().apply {
                        put("id", registrationResponseJson.optString("id"))
                        put("rawId", registrationResponseJson.optString("rawId")) // base64url string
                        put("type", registrationResponseJson.optString("type"))
                        put("response", JSObject().apply {
                            put("attestationObject", responseField.optString("attestationObject"))
                            put("clientDataJSON", responseField.optString("clientDataJSON"))
                        })
                    }

                    call.resolve(passkeyResponse)

                } else {
                    handlePluginError(call, message = "No response data received from passkey registration!")
                }
            } catch (e: CreateCredentialException) {
                handleCreatePasskeyException(call, e)
            } catch (e: Exception) {
                Log.e("PasskeyPlugin", "Unexpected error during passkey creation: ${e.message}", e)
                handlePluginError(call, code = "UNKNOWN_ERROR", message = "An unexpected error occurred during passkey creation: ${e.message ?: "Unknown error"}")
            }
        }
    }

    private fun handleCreatePasskeyException(call: PluginCall, e: CreateCredentialException) {
        Log.e("PasskeyPlugin", "Error during passkey creation: ${e.message}", e)
        when (e) {
            is CreatePublicKeyCredentialDomException -> {
                handlePluginError(call, code = ErrorCodes.DOM, message = (e.errorMessage ?: "Unknown DOM error").toString())
                return
            }
            is CreateCredentialCancellationException -> {
                handlePluginError(call, code = ErrorCodes.CANCELLED, message = "Passkey creation was cancelled by the user.")
                return
            }
            is CreateCredentialInterruptedException -> {
                handlePluginError(call, code = ErrorCodes.INTERRUPTED, message = "Passkey creation was interrupted.")
                return
            }
            is CreateCredentialProviderConfigurationException -> {
                handlePluginError(call, code = ErrorCodes.PROVIDER_CONFIG_ERROR, message = "Provider configuration error: ${e.errorMessage ?: "Unknown error"}")
                return
            }
            is CreateCredentialUnknownException -> {
                handlePluginError(call, code = ErrorCodes.UNKNOWN, message = "An unknown error occurred during passkey creation: ${e.errorMessage ?: "Unknown error"}")
                return
            }
            is CreateCredentialUnsupportedException -> {
                handlePluginError(call, code = ErrorCodes.UNSUPPORTED, message = "Passkey creation is not supported on this device or platform.")
                return
            }
            else -> {
                handlePluginError(call, code = ErrorCodes.UNKNOWN, message = "An unknown error occurred during passkey creation: ${e.message ?: "Unknown error"}")
            }
        }
    }


    @PluginMethod
    fun authenticate(call: PluginCall) {
        val publicKey = call.getObject("publicKey")
//        publicKey.remove("allowCredentials")
//        publicKey.remove("userVerification")
//        publicKey.put("userVerification", "required")
//        publicKey.put("allowCredentials", JSONArray())
        var publicKeyString = publicKey.toString()

        val credentialManager = CredentialManager.Companion.create(context)
        val getCredentialRequest =
            GetCredentialRequest(
                listOf(
                    GetPublicKeyCredentialOption(
                        publicKeyString
                    )
                ), preferImmediatelyAvailableCredentials = true
            )
        mainScope.launch {
            try {
                val activity: Activity? = activity
                if (activity == null) {
                    handlePluginError(call, message = "No activity found to handle passkey authentication!")
                    return@launch
                }
                val credentialResult =
                    activity.let { credentialManager.getCredential(it, getCredentialRequest) }

                val authResponseStr =
                    credentialResult.credential.data.getString("androidx.credentials.BUNDLE_KEY_AUTHENTICATION_RESPONSE_JSON")
                if (authResponseStr == null) {
                    handlePluginError(call, message = "No response from credential manager.")
                    return@launch
                }
                val authResponseJson = JSONObject(authResponseStr)
                val responseField = authResponseJson.optJSONObject("response")
                if (responseField == null) {
                    handlePluginError(call, message = "Malformed response: missing 'response' field")
                    return@launch
                }
                val passkeyResponse = JSObject().apply {
                    put("id", authResponseJson.get("id"))
                    put("rawId", authResponseJson.get("rawId"))
                    put("type", authResponseJson.get("type"))
                    put("response", JSObject().apply {
                        put("clientDataJSON", responseField.optString("clientDataJSON"))
                        put("authenticatorData", responseField.optString("authenticatorData"))
                        put("signature", responseField.optString("signature"))
                        put("userHandle", responseField.optString("userHandle", null))
                    })
                }

                call.resolve(passkeyResponse);

            } catch (e: GetCredentialException) {
                handleAuthenticationError(call, e)
            } catch (e: Exception) {
                Log.e("PasskeyPlugin", "Unexpected error during passkey authentication: ${e.message}", e)
                handlePluginError(call, code = "UNKNOWN_ERROR", message = "An unexpected error occurred during passkey authentication: ${e.message ?: "Unknown error"}")
            }
        }
    }

    private fun handleAuthenticationError(call: PluginCall, e: GetCredentialException) {
        Log.e("PasskeyPlugin", "Error during passkey authentication: ${e.message}", e)
        when (e) {
            is GetPublicKeyCredentialDomException -> {
                handlePluginError(call, code = ErrorCodes.DOM, message = (e.errorMessage ?: "Unknown DOM error").toString())
                return
            }
            is GetCredentialCancellationException -> {
                handlePluginError(call, code = ErrorCodes.CANCELLED, message = "Passkey authentication was cancelled by the user.")
                return
            }
            is GetCredentialInterruptedException -> {
                handlePluginError(call, code = ErrorCodes.INTERRUPTED, message = "Passkey authentication was interrupted.")
                return
            }
            is GetCredentialProviderConfigurationException -> {
                handlePluginError(call, code = ErrorCodes.PROVIDER_CONFIG_ERROR, message = "Provider configuration error: ${e.errorMessage ?: "Unknown error"}")
                return
            }
            is GetCredentialUnknownException -> {
                handlePluginError(call, code = ErrorCodes.UNKNOWN, message = "An unknown error occurred during passkey authentication: ${e.errorMessage ?: "Unknown error"}")
                return
            }
            is GetCredentialUnsupportedException -> {
                handlePluginError(call, code = ErrorCodes.UNSUPPORTED, message = "Passkey authentication is not supported on this device or platform.")
                return
            }
            is NoCredentialException -> {
                handlePluginError(call, code = ErrorCodes.NO_CREDENTIAL, message = "No passkey found for the given request.")
                return
            }
            else -> {
                handlePluginError(call, code = ErrorCodes.UNKNOWN, message = "An unknown error occurred during passkey authentication: ${e.message ?: "Unknown error"}")
            }
        }
    }

    fun handlePluginError(call: PluginCall, code: String = "UNKNOWN_ERROR", message: String) {
        Log.e("PasskeyPlugin", "Error: $message")
        val errorData = JSObject().apply {
            put("code", code)
            put("message", message)
        }
        call.reject(message, code, errorData)
    }
}