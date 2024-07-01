package com.hypto.iam.server.authProviders

import com.hypto.iam.server.ROOT_ORG
import com.hypto.iam.server.configs.AppConfig
import com.hypto.iam.server.exceptions.EntityNotFoundException
import com.hypto.iam.server.security.AuthMetadata
import com.hypto.iam.server.security.AuthenticationException
import com.hypto.iam.server.security.OAuthUserPrincipal
import com.hypto.iam.server.security.TokenCredential
import com.workos.WorkOS
import mu.KotlinLogging
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject
import java.util.UUID
import com.workos.common.exceptions.BadRequestException as WorkOSBadRequestException
import com.workos.common.exceptions.NotFoundException as WorkOSNotFoundException
import com.workos.common.exceptions.UnauthorizedException as WorkOSUnauthorizedException

private val logger = KotlinLogging.logger {}

object WorkOSAuthProvider : BaseAuthProvider("workos"), KoinComponent {
    private val appConfig: AppConfig by inject()
    private val workos: WorkOS by inject()

    @Suppress("SwallowedException")
    override fun getProfileDetails(tokenCredential: TokenCredential): OAuthUserPrincipal {
        return try {
            if (tokenCredential.value.isNullOrEmpty()) {
                throw WorkOSUnauthorizedException("Token credential value cannot be null or empty", UUID.randomUUID().toString())
            }
            val profileAndToken = workos.sso.getProfileAndToken(tokenCredential.value, appConfig.workOS.clientId)
            OAuthUserPrincipal(
                tokenCredential,
                ROOT_ORG,
                profileAndToken.profile.email,
                profileAndToken.profile.firstName ?: profileAndToken.profile.lastName ?: "",
                "",
                this.providerName,
                AuthMetadata(profileAndToken.profile.id),
            )
        } catch (e: WorkOSBadRequestException) {
            logger.error { "Bad Request - ${e.message}" }
            throw AuthenticationException(e.message ?: "Invalid access token")
        } catch (e: WorkOSUnauthorizedException) {
            logger.error { "Unauthorized - ${e.message}" }
            throw AuthenticationException(e.message ?: "Unauthorized")
        } catch (e: WorkOSNotFoundException) {
            logger.error { "Profile not found - ${e.message}" }
            throw EntityNotFoundException(e.message ?: "Profile not found")
        }
    }
}
