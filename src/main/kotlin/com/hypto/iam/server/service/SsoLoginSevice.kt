package com.hypto.iam.server.service

import com.hypto.iam.server.configs.AppConfig
import com.hypto.iam.server.exceptions.EntityNotFoundException
import com.hypto.iam.server.exceptions.UnknownException
import com.hypto.iam.server.models.AuthUrlResponse
import com.hypto.iam.server.models.SsoLoginRequest
import com.hypto.iam.server.security.AuthenticationException
import com.workos.WorkOS
import com.workos.common.exceptions.BadRequestException
import com.workos.common.exceptions.NotFoundException
import com.workos.common.exceptions.UnauthorizedException
import com.workos.organizations.OrganizationsApi
import mu.KotlinLogging
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject

private val logger = KotlinLogging.logger {}

class SsoLoginServiceImpl : SsoLoginService, KoinComponent {
    private val appConfig: AppConfig by inject()
    private val workos: WorkOS by inject()

    companion object {
        private const val WORKOS_STATE = "workos"
        private const val UNKNOWN_ERROR = "Unknown error occurred"
        private const val ENTITY_NOT_FOUND = "Entity not found"
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    override suspend fun getAuthUrlForDomain(
        ssoLoginRequest: SsoLoginRequest,
    ): AuthUrlResponse {
        return try {
            val domains = listOf(ssoLoginRequest.domain)
            val options = OrganizationsApi.ListOrganizationsOptions.builder().domains(domains).build()
            val organizations = workos.organizations.listOrganizations(options)
            require(organizations.data.isNotEmpty()) {
                "SSO not configured for ${ssoLoginRequest.domain}. Please contact administrator."
            }
            val url = workos.sso.getAuthorizationUrl(appConfig.workOS.clientId, ssoLoginRequest.redirectUri).organization(organizations.data[0].id).state(WORKOS_STATE).build()
            AuthUrlResponse(url)
        } catch (e: UnauthorizedException) {
            logger.error { "Unauthorized - ${e.message}" }
            throw AuthenticationException(e.message ?: "Unauthorized")
        } catch (e: BadRequestException) {
            logger.error { "Bad request - ${e.message}" }
            throw io.ktor.server.plugins.BadRequestException("Error while getting authentication URL from WorkOS")
        } catch (e: NotFoundException) {
            logger.error { "$ENTITY_NOT_FOUND - ${e.message}" }
            throw EntityNotFoundException(ENTITY_NOT_FOUND)
        } catch (e: IllegalArgumentException) {
            logger.error { e.message ?: "Illegal argument received" }
            throw IllegalArgumentException(e.message ?: "Illegal argument received")
        } catch (e: Exception) {
            logger.error { "$UNKNOWN_ERROR - ${e.message}" }
            throw UnknownException(UNKNOWN_ERROR)
        }
    }
}

interface SsoLoginService {
    suspend fun getAuthUrlForDomain(
        ssoLoginRequest: SsoLoginRequest,
    ): AuthUrlResponse
}
