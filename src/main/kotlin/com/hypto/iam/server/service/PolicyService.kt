package com.hypto.iam.server.service

import com.hypto.iam.server.db.repositories.PoliciesRepo
import com.hypto.iam.server.db.repositories.PrincipalPoliciesRepo
import com.hypto.iam.server.db.repositories.RawPolicyPayload
import com.hypto.iam.server.db.tables.records.PoliciesRecord
import com.hypto.iam.server.exceptions.EntityAlreadyExistsException
import com.hypto.iam.server.exceptions.EntityNotFoundException
import com.hypto.iam.server.extensions.PaginationContext
import com.hypto.iam.server.extensions.from
import com.hypto.iam.server.models.BaseSuccessResponse
import com.hypto.iam.server.models.Policy
import com.hypto.iam.server.models.PolicyPaginatedResponse
import com.hypto.iam.server.models.PolicyStatement
import com.hypto.iam.server.models.UpdatePolicyRequest
import com.hypto.iam.server.utils.IamResources
import com.hypto.iam.server.utils.ResourceHrn
import com.hypto.iam.server.utils.policy.PolicyBuilder
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject

// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
class PolicyServiceImpl : KoinComponent, PolicyService {
    private val policyRepo: PoliciesRepo by inject()
    private val principalPolicyRepo: PrincipalPoliciesRepo by inject()

    override suspend fun createPolicy(
        organizationId: String,
        name: String,
        description: String?,
        statements: List<PolicyStatement>,
    ): Policy {
        val policyHrn = ResourceHrn(organizationId, "", IamResources.POLICY, name)
        if (policyRepo.existsById(policyHrn.toString())) {
            throw EntityAlreadyExistsException("Policy with name [$name] already exists")
        }

        // TODO: Validate policy statements (actions and resourceTypes)
        val newPolicyBuilder = PolicyBuilder(policyHrn)
        statements.forEach { newPolicyBuilder.withStatement(it) }

        val policyRecord = policyRepo.create(policyHrn, description, newPolicyBuilder.build())
        return Policy.from(policyRecord)
    }

    override suspend fun batchCreatePolicyRaw(
        organizationId: String,
        rawPolicyPayloadsList: List<RawPolicyPayload>,
    ): List<PoliciesRecord> {
        val policyHrnStrings = rawPolicyPayloadsList.map { it.hrn.toString() }

        if (policyRepo.fetchByHrns(policyHrnStrings).isNotEmpty()) {
            throw EntityAlreadyExistsException("One or more policies already exists")
        }

        return policyRepo.batchCreate(rawPolicyPayloadsList)
    }

    override suspend fun getPolicy(
        organizationId: String,
        name: String,
    ): Policy {
        val policyRecord =
            policyRepo.fetchByHrn(
                ResourceHrn(organizationId, "", IamResources.POLICY, name).toString(),
            ) ?: throw EntityNotFoundException("Policy not found")
        return Policy.from(policyRecord)
    }

    override suspend fun updatePolicy(
        organizationId: String,
        name: String,
        updatePolicyRequest: UpdatePolicyRequest,
    ): Policy {
        val policyHrn = ResourceHrn(organizationId, "", IamResources.POLICY, name)
        val policyHrnStr = policyHrn.toString()

        val policyString =
            if (updatePolicyRequest.statements != null) {
                // TODO: Validate policy statements (actions and resourceTypes)
                PolicyBuilder(policyHrn).let { builder ->
                    updatePolicyRequest.statements.forEach { builder.withStatement(it) }
                    builder.build()
                }
            } else {
                null
            }

        val policyRecord =
            policyRepo.update(
                policyHrnStr,
                description = updatePolicyRequest.description,
                statements = policyString,
            )
        policyRecord ?: throw EntityNotFoundException("cannot find policy: $name")
        return Policy.from(policyRecord)
    }

    override suspend fun deletePolicy(
        organizationId: String,
        name: String,
    ): BaseSuccessResponse {
        val policyHrnStr = ResourceHrn(organizationId, "", IamResources.POLICY, name).toString()
        if (!policyRepo.deleteByHrn(policyHrnStr)) {
            throw EntityNotFoundException("Policy not found")
        }

        return BaseSuccessResponse(true)
    }

    override suspend fun getPoliciesByUser(
        organizationId: String,
        userId: String,
        context: PaginationContext,
    ): PolicyPaginatedResponse {
        val policies =
            principalPolicyRepo
                .fetchPoliciesByUserHrnPaginated(
                    ResourceHrn(organizationId, "", IamResources.USER, userId).toString(),
                    context,
                )
        val newContext = PaginationContext.from(policies.lastOrNull()?.hrn, context)
        return PolicyPaginatedResponse(policies.map { Policy.from(it) }, newContext.nextToken, newContext.toOptions())
    }

    override suspend fun listPolicies(
        organizationId: String,
        context: PaginationContext,
    ): PolicyPaginatedResponse {
        val policies = policyRepo.fetchByOrganizationIdPaginated(organizationId, context)
        val newContext = PaginationContext.from(policies.lastOrNull()?.hrn, context)
        return PolicyPaginatedResponse(policies.map { Policy.from(it) }, newContext.nextToken, newContext.toOptions())
    }
}

interface PolicyService {
    suspend fun createPolicy(
        organizationId: String,
        name: String,
        description: String?,
        statements: List<PolicyStatement>,
    ): Policy

    suspend fun getPolicy(
        organizationId: String,
        name: String,
    ): Policy

    suspend fun updatePolicy(
        organizationId: String,
        name: String,
        updatePolicyRequest: UpdatePolicyRequest,
    ): Policy

    suspend fun deletePolicy(
        organizationId: String,
        name: String,
    ): BaseSuccessResponse

    suspend fun getPoliciesByUser(
        organizationId: String,
        userId: String,
        context: PaginationContext,
    ): PolicyPaginatedResponse

    suspend fun listPolicies(
        organizationId: String,
        context: PaginationContext,
    ): PolicyPaginatedResponse

    suspend fun batchCreatePolicyRaw(
        organizationId: String,
        rawPolicyPayloadsList: List<RawPolicyPayload>,
    ): List<PoliciesRecord>
}
