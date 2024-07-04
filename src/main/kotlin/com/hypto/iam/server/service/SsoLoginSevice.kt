package com.hypto.iam.server.service

import com.hypto.iam.server.configs.AppConfig
import com.hypto.iam.server.exceptions.EntityNotFoundException
import com.hypto.iam.server.models.AuthUrlResponse
import com.hypto.iam.server.models.SsoLoginRequest
import com.hypto.iam.server.security.AuthenticationException
import com.workos.WorkOS
import com.workos.sso.SsoApi
import com.workos.sso.models.ConnectionState
import io.ktor.server.plugins.BadRequestException
import mu.KotlinLogging
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject
import java.util.UUID
import com.workos.common.exceptions.BadRequestException as WorkOSBadRequestException
import com.workos.common.exceptions.NotFoundException as WorkOSNotFoundException
import com.workos.common.exceptions.UnauthorizedException as WorkOSUnauthorizedException

private val logger = KotlinLogging.logger {}

class SsoLoginServiceImpl : SsoLoginService, KoinComponent {
    private val appConfig: AppConfig by inject()
    private val workos: WorkOS by inject()

    companion object {
        private const val WORKOS_STATE = "workos"
        private const val ENTITY_NOT_FOUND = "Entity not found"
    }

    @Suppress("SwallowedException")
    override suspend fun getAuthUrlForDomain(
        ssoLoginRequest: SsoLoginRequest,
    ): AuthUrlResponse {
        return try {
            val connectionOptions = SsoApi.ListConnectionsOptions.builder().domain(ssoLoginRequest.domain).build()
            val connections = workos.sso.listConnections(connectionOptions)
            if (connections.data.isEmpty() || connections.data[0].state != ConnectionState.Active) {
                throw WorkOSBadRequestException("SSO not configured for ${ssoLoginRequest.domain}. Please contact administrator.", null, null, UUID.randomUUID().toString())
            }
            val url =
                workos.sso
                    .getAuthorizationUrl(appConfig.workOS.clientId, ssoLoginRequest.redirectUri)
                    .connection(connections.data[0].id)
                    .state(WORKOS_STATE)
                    .loginHint(ssoLoginRequest.email)
                    .build()
            AuthUrlResponse(url)
        } catch (e: WorkOSUnauthorizedException) {
            logger.error { "Unauthorized - ${e.message}" }
            throw AuthenticationException(e.message ?: "Unauthorized")
        } catch (e: WorkOSBadRequestException) {
            logger.error { "Bad request - ${e.message}" }
            throw BadRequestException(e.message ?: "Error while getting authentication URL from WorkOS")
        } catch (e: WorkOSNotFoundException) {
            logger.error { "$ENTITY_NOT_FOUND - ${e.message}" }
            throw EntityNotFoundException(ENTITY_NOT_FOUND)
        }
    }
}

interface SsoLoginService {
    suspend fun getAuthUrlForDomain(
        ssoLoginRequest: SsoLoginRequest,
    ): AuthUrlResponse
}
