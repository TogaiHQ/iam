package com.hypto.iam.server.service

import com.hypto.iam.server.db.repositories.CredentialsRepo
import com.hypto.iam.server.security.TokenCredential
import com.hypto.iam.server.security.TokenType
import com.hypto.iam.server.security.UserPrincipal
import com.hypto.iam.server.security.UsernamePasswordCredential
import com.hypto.iam.server.utils.ResourceHrn
import com.hypto.iam.server.utils.measureTimedValue
import com.hypto.iam.server.utils.policy.PolicyBuilder
import com.hypto.iam.server.utils.policy.PolicyVariables
import com.hypto.iam.server.validators.validate
import mu.KotlinLogging
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject

private val logger = KotlinLogging.logger("service.UserPrincipalServiceImpl")

class UserPrincipalServiceImpl : KoinComponent, UserPrincipalService {
    private val credentialsRepo: CredentialsRepo by inject()
    private val principalPolicyService: PrincipalPolicyService by inject()
    private val tokenService: TokenService by inject()
    private val usersService: UsersService by inject()

    override suspend fun getUserPrincipalByRefreshToken(
        tokenCredential: TokenCredential,
    ): UserPrincipal? {
        return credentialsRepo.fetchByRefreshToken(tokenCredential.value!!)?.let { credential ->
            UserPrincipal(
                tokenCredential = tokenCredential,
                hrnStr = credential.userHrn,
                policies = principalPolicyService.fetchEntitlements(credential.userHrn),
            )
        }
    }

    override suspend fun getUserPrincipalByJwtToken(
        tokenCredential: TokenCredential,
        deepCheck: Boolean,
    ): UserPrincipal =
        measureTimedValue("TokenService.getUserPrincipalByJwtToken.$deepCheck", logger) {
            val token = tokenService.validateJwtToken(tokenCredential.value!!)
            val userHrnStr: String = token.body[TokenServiceImpl.USER_CLAIM, String::class.java]
            val creatorHrnStr: String? = token.body[TokenServiceImpl.ON_BEHALF_CLAIM, String::class.java]
            val entitlements: String = token.body[TokenServiceImpl.ENTITLEMENTS_CLAIM, String::class.java]
            val hrn = ResourceHrn(userHrnStr)
            val organizationId = hrn.organization
            return UserPrincipal(
                tokenCredential,
                userHrnStr,
                token.body,
                if (deepCheck && (creatorHrnStr == null)) {
                    principalPolicyService.fetchEntitlements(userHrnStr)
                } else {
                    PolicyBuilder(policyStr = entitlements).withPolicyVariables(PolicyVariables(organizationId, userHrnStr, hrn.resourceInstance))
                },
            )
        }

    override suspend fun getUserPrincipalByCredentials(
        organizationId: String,
        subOrganizationId: String?,
        userName: String,
        password: String,
    ): UserPrincipal =
        measureTimedValue("TokenService.getUserPrincipalByCredentials", logger) {
            val user = usersService.authenticate(organizationId, subOrganizationId, userName, password)
            return UserPrincipal(
                tokenCredential = TokenCredential(userName, TokenType.BASIC),
                hrnStr = user.hrn,
                policies = principalPolicyService.fetchEntitlements(user.hrn),
            )
        }

    override suspend fun getUserPrincipalByCredentials(
        credentials: UsernamePasswordCredential,
    ): UserPrincipal {
        val validCredentials = credentials.validate()
        val user = usersService.authenticate(null, validCredentials.username, validCredentials.password)
        return UserPrincipal(
            tokenCredential = TokenCredential(validCredentials.username, TokenType.BASIC),
            hrnStr = user.hrn,
            policies = principalPolicyService.fetchEntitlements(user.hrn),
        )
    }
}

interface UserPrincipalService {
    suspend fun getUserPrincipalByRefreshToken(tokenCredential: TokenCredential): UserPrincipal?

    suspend fun getUserPrincipalByJwtToken(
        tokenCredential: TokenCredential,
        deepCheck: Boolean = false,
    ): UserPrincipal

    suspend fun getUserPrincipalByCredentials(
        organizationId: String,
        subOrganizationId: String?,
        userName: String,
        password: String,
    ): UserPrincipal

    suspend fun getUserPrincipalByCredentials(credentials: UsernamePasswordCredential): UserPrincipal
}
