package com.hypto.iam.server.service

import com.hypto.iam.server.configs.AppConfig
import com.hypto.iam.server.models.AuthUrlResponse
import com.hypto.iam.server.models.SsoLoginRequest
import com.workos.WorkOS
import com.workos.organizations.OrganizationsApi
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject

class SsoLoginServiceImpl : SsoLoginService, KoinComponent {
    private val appConfig: AppConfig by inject()

    override suspend fun getAuthUrlForDomain(
        ssoLoginRequest: SsoLoginRequest,
    ): AuthUrlResponse {
        val workos = WorkOS(appConfig.workOS.secretKey)
        val domains = listOf(ssoLoginRequest.domain)
        val options = OrganizationsApi.ListOrganizationsOptions.builder().domains(domains).build()
        val organizations = workos.organizations.listOrganizations(options)
        require(organizations.data.isNotEmpty()) {
            "SSO not configured for this domain"
        }
        val url = workos.sso.getAuthorizationUrl(appConfig.workOS.clientId, ssoLoginRequest.redirectUri).organization(organizations.data[0].id).state("workos").build()
        return AuthUrlResponse(url)
    }
}

interface SsoLoginService {
    suspend fun getAuthUrlForDomain(
        ssoLoginRequest: SsoLoginRequest,
    ): AuthUrlResponse
}
