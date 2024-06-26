package com.hypto.iam.server.authProviders

import com.hypto.iam.server.ROOT_ORG
import com.hypto.iam.server.configs.AppConfig
import com.hypto.iam.server.exceptions.EntityNotFoundException
import com.hypto.iam.server.exceptions.UnknownException
import com.hypto.iam.server.security.AuthMetadata
import com.hypto.iam.server.security.AuthenticationException
import com.hypto.iam.server.security.OAuthUserPrincipal
import com.hypto.iam.server.security.TokenCredential
import com.workos.WorkOS
import com.workos.common.exceptions.NotFoundException
import com.workos.common.exceptions.UnauthorizedException
import mu.KotlinLogging
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject
import java.util.UUID

private val logger = KotlinLogging.logger {}

object WorkOSAuthProvider : BaseAuthProvider("workos"), KoinComponent {
    private val appConfig: AppConfig by inject()
    private val workos: WorkOS by inject()

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    override fun getProfileDetails(tokenCredential: TokenCredential): OAuthUserPrincipal {
        return try {
            if (tokenCredential.value.isNullOrEmpty()) {
                throw UnauthorizedException("Token credential value cannot be null or empty", UUID.randomUUID().toString())
            }
            val profileAndToken = workos.sso.getProfileAndToken(tokenCredential.value, appConfig.workOS.clientId)
            OAuthUserPrincipal(
                tokenCredential,
                ROOT_ORG,
                profileAndToken.profile.email,
                profileAndToken.profile.firstName ?: profileAndToken.profile.lastName ?: "",
                "",
                this.providerName,
                AuthMetadata(profileAndToken.profile.connectionType + "-" + profileAndToken.profile.connectionId),
            )
        } catch (e: UnauthorizedException) {
            logger.error { "Unauthorized - ${e.message}" }
            throw AuthenticationException(e.message ?: "Unauthorized")
        } catch (e: NotFoundException) {
            logger.error { "Profile not found - ${e.message}" }
            throw EntityNotFoundException("Profile not found")
        } catch (e: IllegalArgumentException) {
            logger.error { e.message ?: "Illegal argument received" }
            throw IllegalArgumentException(e.message ?: "Illegal argument received")
        } catch (e: Exception) {
            logger.error { "Unknown error occurred - ${e.message}" }
            throw UnknownException("Unknown error occurred")
        }
    }
}
