package com.hypto.iam.server.authProviders

import com.hypto.iam.server.ROOT_ORG
import com.hypto.iam.server.configs.AppConfig
import com.hypto.iam.server.security.AuthMetadata
import com.hypto.iam.server.security.OAuthUserPrincipal
import com.hypto.iam.server.security.TokenCredential
import com.workos.WorkOS
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject

object WorkOSAuthProvider : BaseAuthProvider("workos"), KoinComponent {
    private val appConfig: AppConfig by inject()

    override fun getProfileDetails(tokenCredential: TokenCredential): OAuthUserPrincipal {
        val workos = WorkOS(appConfig.workOS.secretKey)
        require(!tokenCredential.value.isNullOrEmpty()) {
            "Token credential value cannot be null or empty"
        }
        val profileAndToken = workos.sso.getProfileAndToken(tokenCredential.value, appConfig.workOS.clientId)
        return OAuthUserPrincipal(
            tokenCredential,
            ROOT_ORG,
            profileAndToken.profile.email,
            profileAndToken.profile.firstName ?: profileAndToken.profile.lastName ?: "",
            "",
            this.providerName,
            AuthMetadata(profileAndToken.profile.connectionType + "-" + profileAndToken.profile.connectionId),
        )
    }
}
