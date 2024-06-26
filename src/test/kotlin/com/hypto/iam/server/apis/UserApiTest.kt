package com.hypto.iam.server.apis

import com.google.gson.Gson
import com.hypto.iam.server.Constants
import com.hypto.iam.server.helpers.AbstractContainerBaseTest
import com.hypto.iam.server.helpers.DataSetupHelperV2.createAndAttachPolicy
import com.hypto.iam.server.helpers.DataSetupHelperV2.createOrganization
import com.hypto.iam.server.helpers.DataSetupHelperV2.createResource
import com.hypto.iam.server.helpers.DataSetupHelperV2.createUser
import com.hypto.iam.server.helpers.DataSetupHelperV2.deleteOrganization
import com.hypto.iam.server.idp.CognitoConstants
import com.hypto.iam.server.models.BaseSuccessResponse
import com.hypto.iam.server.models.ChangeUserPasswordRequest
import com.hypto.iam.server.models.CreateUserRequest
import com.hypto.iam.server.models.CreateUserResponse
import com.hypto.iam.server.models.PolicyAssociationRequest
import com.hypto.iam.server.models.ResetPasswordRequest
import com.hypto.iam.server.models.UpdateUserRequest
import com.hypto.iam.server.models.User
import com.hypto.iam.server.models.UserPaginatedResponse
import com.hypto.iam.server.models.VerifyEmailRequest
import com.hypto.iam.server.utils.IamResources
import com.hypto.iam.server.utils.IdGenerator
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.patch
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.config.ApplicationConfig
import io.ktor.server.testing.testApplication
import io.mockk.coEvery
import io.mockk.slot
import io.mockk.verify
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.koin.core.component.get
import org.koin.test.inject
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminCreateUserRequest
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminDeleteUserRequest
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserRequest
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserResponse
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminInitiateAuthRequest
import software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListUsersRequest
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListUsersResponse
import software.amazon.awssdk.services.cognitoidentityprovider.model.NotAuthorizedException
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserNotFoundException
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserType
import software.amazon.awssdk.services.cognitoidentityprovider.model.UsernameExistsException
import java.time.Instant
import java.util.Base64
import kotlin.test.assertTrue

class UserApiTest : AbstractContainerBaseTest() {
    private val gson: Gson by inject()

    @Nested
    @DisplayName("Create user API tests")
    inner class CreateUserTest {
        @Test
        fun `create user success case`() {
            val testEmail = "test-user-email" + IdGenerator.randomId() + "@hypto.in"
            val createUserRequest =
                CreateUserRequest(
                    preferredUsername = "testUserName",
                    name = "lorem ipsum",
                    password = "testPassword@Hash1",
                    email = testEmail,
                    status = CreateUserRequest.Status.enabled,
                    phone = "+919626012778",
                    verified = true,
                    loginAccess = true,
                )
            testApplication {
                environment {
                    config = ApplicationConfig("application-custom.conf")
                }
                val (organizationResponse, _) = createOrganization()
                val organization = organizationResponse.organization
                val rootUserToken = organizationResponse.rootUserToken

                coEvery {
                    cognitoClient.adminGetUser(any<AdminGetUserRequest>())
                } returns
                    AdminGetUserResponse.builder()
                        .enabled(true)
                        .username(organization.rootUser.username)
                        .userAttributes(
                            AttributeType.builder().name(CognitoConstants.ATTRIBUTE_EMAIL)
                                .value(organization.rootUser.email).build(),
                            AttributeType.builder().name(CognitoConstants.ATTRIBUTE_PREFERRED_USERNAME)
                                .value(organization.rootUser.phone).build(),
                        )
                        .userCreateDate(Instant.now())
                        .build()

                createResource(organization.id, rootUserToken)

                val response =
                    client.post("/organizations/${organization.id}/users") {
                        header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                        header(HttpHeaders.Authorization, "Bearer $rootUserToken")
                        setBody(gson.toJson(createUserRequest))
                    }
                val responseBody = gson.fromJson(response.bodyAsText(), CreateUserResponse::class.java)
                assertEquals(HttpStatusCode.Created, response.status)
                assertEquals(
                    ContentType.Application.Json,
                    response.contentType(),
                )
                assertEquals(
                    organization.id,
                    response.headers[Constants.X_ORGANIZATION_HEADER],
                )

                assertEquals(createUserRequest.preferredUsername, responseBody.user.preferredUsername)
                assertEquals(createUserRequest.email, responseBody.user.email)
                assertEquals(User.Status.enabled.toString(), responseBody.user.status.toString())
                assertEquals(createUserRequest.verified, responseBody.user.verified)

                deleteOrganization(organization.id)
            }
        }

        @Test
        fun `create user without preferred username`() {
            val testEmail = "test-user-email" + IdGenerator.randomId() + "@hypto.in"
            val createUserRequest =
                CreateUserRequest(
                    name = "lorem ipsum",
                    password = "testPassword@Hash1",
                    email = testEmail,
                    status = CreateUserRequest.Status.enabled,
                    phone = "+919626012778",
                    verified = true,
                    loginAccess = true,
                )
            testApplication {
                environment {
                    config = ApplicationConfig("application-custom.conf")
                }
                val (organizationResponse, _) = createOrganization()
                val organization = organizationResponse.organization
                val rootUserToken = organizationResponse.rootUserToken

                coEvery {
                    cognitoClient.adminGetUser(any<AdminGetUserRequest>())
                } returns
                    AdminGetUserResponse.builder()
                        .enabled(true)
                        .username(organization.rootUser.username)
                        .userAttributes(
                            AttributeType.builder().name(CognitoConstants.ATTRIBUTE_EMAIL)
                                .value(organization.rootUser.email).build(),
                            AttributeType.builder().name(CognitoConstants.ATTRIBUTE_PREFERRED_USERNAME)
                                .value(organization.rootUser.phone).build(),
                        )
                        .userCreateDate(Instant.now())
                        .build()

                createResource(organization.id, rootUserToken)

                val response =
                    client.post("/organizations/${organization.id}/users") {
                        header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                        header(HttpHeaders.Authorization, "Bearer $rootUserToken")
                        setBody(gson.toJson(createUserRequest))
                    }
                val responseBody = gson.fromJson(response.bodyAsText(), CreateUserResponse::class.java)
                assertEquals(HttpStatusCode.Created, response.status)
                assertEquals(
                    ContentType.Application.Json,
                    response.contentType(),
                )
                assertEquals(
                    organization.id,
                    response.headers[Constants.X_ORGANIZATION_HEADER],
                )

                assertEquals(null, responseBody.user.preferredUsername)
                assertEquals(createUserRequest.email, responseBody.user.email)
                assertEquals(User.Status.enabled.toString(), responseBody.user.status.toString())
                assertEquals(createUserRequest.verified, responseBody.user.verified)

                deleteOrganization(organization.id)
            }
        }

        @Test
        fun `create user with same preferred username - failure`() {
            val testEmail = "test-user-email" + IdGenerator.randomId() + "@hypto.in"
            val preferredUsername = "testUserName"
            val createUserRequest =
                CreateUserRequest(
                    name = "lorem ipsum",
                    preferredUsername = preferredUsername,
                    password = "testPassword@Hash1",
                    email = testEmail,
                    status = CreateUserRequest.Status.enabled,
                    phone = "+919626012778",
                    verified = true,
                    loginAccess = true,
                )
            testApplication {
                environment {
                    config = ApplicationConfig("application-custom.conf")
                }
                val (organizationResponse, _) = createOrganization(preferredUsername)
                val organization = organizationResponse.organization
                val rootUserToken = organizationResponse.rootUserToken

                coEvery {
                    cognitoClient.adminCreateUser(any<AdminCreateUserRequest>())
                } throws
                    UsernameExistsException.builder()
                        .build()
                coEvery {
                    cognitoClient.adminGetUser(any<AdminGetUserRequest>())
                } throws
                    UserNotFoundException.builder()
                        .build()

                createResource(organization.id, rootUserToken)

                val response =
                    client.post("/organizations/${organization.id}/users") {
                        header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                        header(HttpHeaders.Authorization, "Bearer $rootUserToken")
                        setBody(gson.toJson(createUserRequest))
                    }
                assertEquals(HttpStatusCode.BadRequest, response.status)
                assertEquals(
                    ContentType.Application.Json,
                    response.contentType(),
                )

                deleteOrganization(organization.id)
            }
        }

        @Test
        fun `create user with validation error case`() {
            val testEmail = "test-user-email" + IdGenerator.randomId() + "hypto.in"
            val createUserRequest =
                CreateUserRequest(
                    preferredUsername = "testUserName",
                    name = "lorem ipsum",
                    password = "testPassword@ash",
                    email = testEmail,
                    status = CreateUserRequest.Status.enabled,
                    phone = "+919999999999",
                    loginAccess = true,
                )
            testApplication {
                environment {
                    config = ApplicationConfig("application-custom.conf")
                }
                val (organizationResponse, _) = createOrganization()
                val organization = organizationResponse.organization
                val rootUserToken = organizationResponse.rootUserToken
                createResource(organization.id, rootUserToken)

                val response =
                    client.post("/organizations/${organization.id}/users") {
                        header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                        header(HttpHeaders.Authorization, "Bearer $rootUserToken")
                        setBody(gson.toJson(createUserRequest))
                    }

                assertEquals(HttpStatusCode.BadRequest, response.status)
                deleteOrganization(organization.id)
            }
        }

        @Test
        fun `create user without login access - success case`() {
            val createUserRequest =
                CreateUserRequest(
                    preferredUsername = "testUserName",
                    name = "lorem ipsum",
                    status = CreateUserRequest.Status.enabled,
                    verified = true,
                    loginAccess = false,
                )
            testApplication {
                environment {
                    config = ApplicationConfig("application-custom.conf")
                }
                val (organizationResponse, rootUser) = createOrganization()
                val organization = organizationResponse.organization
                val rootUserToken = organizationResponse.rootUserToken

                createResource(organization.id, rootUserToken)

                val response =
                    client.post("/organizations/${organization.id}/users") {
                        header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                        header(HttpHeaders.Authorization, "Bearer $rootUserToken")
                        setBody(gson.toJson(createUserRequest))
                    }
                val responseBody = gson.fromJson(response.bodyAsText(), CreateUserResponse::class.java)
                assertEquals(HttpStatusCode.Created, response.status)
                assertEquals(
                    ContentType.Application.Json,
                    response.contentType(),
                )
                assertEquals(
                    organization.id,
                    response.headers[Constants.X_ORGANIZATION_HEADER],
                )

                assertEquals(createUserRequest.preferredUsername, responseBody.user.preferredUsername)
                assertEquals(createUserRequest.email, responseBody.user.email)
                assertEquals(createUserRequest.name, responseBody.user.name)
                assertEquals(User.Status.enabled.toString(), responseBody.user.status.toString())
                assertEquals(createUserRequest.verified, responseBody.user.verified)
                assertEquals(createUserRequest.loginAccess, responseBody.user.loginAccess)

                deleteOrganization(organization.id)
            }
        }

        @Test
        fun `create user without login access - request validation error`() {
            val createUserRequest =
                CreateUserRequest(
                    preferredUsername = "testUserName",
                    name = "lorem ipsum",
                    status = CreateUserRequest.Status.enabled,
                    verified = true,
                    email = "testuser@test.com",
                    password = "testPassword@ash",
                    loginAccess = false,
                )
            testApplication {
                environment {
                    config = ApplicationConfig("application-custom.conf")
                }
                val (organizationResponse, rootUser) = createOrganization()
                val organization = organizationResponse.organization
                val rootUserToken = organizationResponse.rootUserToken

                createResource(organization.id, rootUserToken)

                val response =
                    client.post("/organizations/${organization.id}/users") {
                        header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                        header(HttpHeaders.Authorization, "Bearer $rootUserToken")
                        setBody(gson.toJson(createUserRequest))
                    }
                assertEquals(HttpStatusCode.BadRequest, response.status)
                assertEquals(
                    ContentType.Application.Json,
                    response.contentType(),
                )

                deleteOrganization(organization.id)
            }
        }
    }

    @Nested
    @DisplayName("Get user API tests")
    inner class GetUserTest {
        @Test
        fun `get user request success case`() {
            val testEmail = "test-user-email" + IdGenerator.randomId() + "@hypto.in"
            val createUserRequest =
                CreateUserRequest(
                    preferredUsername = "testUserName",
                    name = "lorem ipsum",
                    password = "testPassword@Hash1",
                    email = testEmail,
                    status = CreateUserRequest.Status.enabled,
                    phone = "+919626012778",
                    loginAccess = true,
                )
            testApplication {
                environment {
                    config = ApplicationConfig("application-custom.conf")
                }
                val (organizationResponse, _) = createOrganization()
                val organization = organizationResponse.organization
                val rootUserToken = organizationResponse.rootUserToken

                // Create user
                val (user1, _) =
                    createUser(
                        orgId = organization.id,
                        bearerToken = rootUserToken,
                        createUserRequest = createUserRequest,
                    )

                coEvery {
                    cognitoClient.adminGetUser(any<AdminGetUserRequest>())
                } returns
                    AdminGetUserResponse.builder()
                        .enabled(true)
                        .username(user1.username)
                        .userAttributes(
                            AttributeType.builder().name(CognitoConstants.ATTRIBUTE_EMAIL)
                                .value(user1.email).build(),
                            AttributeType.builder().name(CognitoConstants.ATTRIBUTE_PREFERRED_USERNAME)
                                .value(user1.preferredUsername).build(),
                        )
                        .userCreateDate(Instant.now())
                        .build()

                // Get user
                val response =
                    client.get("/organizations/${organization.id}/users/${user1.username}") {
                        header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                        header(HttpHeaders.Authorization, "Bearer $rootUserToken")
                    }
                val responseBody = gson.fromJson(response.bodyAsText(), User::class.java)
                assertEquals(HttpStatusCode.OK, response.status)
                assertEquals(
                    ContentType.Application.Json,
                    response.contentType(),
                )

                assertEquals(createUserRequest.preferredUsername, responseBody.preferredUsername)
                assertEquals(false, responseBody.verified)
                deleteOrganization(organization.id)
            }
        }

        @Test
        fun `get user with unauthorized access`() {
            val testEmail = "test-user-email" + IdGenerator.randomId() + "@hypto.in"
            val createUserRequest =
                CreateUserRequest(
                    preferredUsername = "testUserName",
                    name = "lorem ipsum",
                    password = "testPassword@123",
                    email = testEmail,
                    status = CreateUserRequest.Status.enabled,
                    phone = "+919626012778",
                    loginAccess = true,
                )
            testApplication {
                environment {
                    config = ApplicationConfig("application-custom.conf")
                }
                val (organizationResponse, _) = createOrganization()
                val organization = organizationResponse.organization
                val rootUserToken = organizationResponse.rootUserToken

                // Create user
                val (user1, _) =
                    createUser(
                        orgId = organization.id,
                        bearerToken = rootUserToken,
                        createUserRequest = createUserRequest,
                    )

                // Get user
                val response =
                    client.get("/organizations/${organization.id}/users/${user1.username}") {
                        header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                        header(HttpHeaders.Authorization, "Bearer badSecret")
                    }
                assertEquals(HttpStatusCode.Unauthorized, response.status)
                deleteOrganization(organization.id)
            }
        }
    }

    @Nested
    @DisplayName("delete user API tests")
    inner class DeleteUserTest {
        @Test
        fun `delete user success case`() {
            val testEmail = "test-user-email" + IdGenerator.randomId() + "@hypto.in"
            val createUserRequest =
                CreateUserRequest(
                    preferredUsername = "testUserName",
                    name = "lorem ipsum",
                    password = "testPassword@Hash1",
                    email = testEmail,
                    status = CreateUserRequest.Status.enabled,
                    phone = "+919626012778",
                    loginAccess = true,
                )
            testApplication {
                environment {
                    config = ApplicationConfig("application-custom.conf")
                }
                val (organizationResponse, _) = createOrganization()
                val organization = organizationResponse.organization
                val rootUserToken = organizationResponse.rootUserToken

                // Create user
                val (user1, _) =
                    createUser(
                        orgId = organization.id,
                        bearerToken = rootUserToken,
                        createUserRequest = createUserRequest,
                    )

                // Delete user
                val response =
                    client.delete("/organizations/${organization.id}/users/${user1.username}") {
                        header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                        header(HttpHeaders.Authorization, "Bearer $rootUserToken")
                    }
                assertEquals(HttpStatusCode.OK, response.status)

                // Verify the value from mocks
                val slot = slot<AdminDeleteUserRequest>()
                verify { get<CognitoIdentityProviderClient>().adminDeleteUser(capture(slot)) }
                val adminUserRequest = slot.captured
                assertEquals(user1.username, adminUserRequest.username())
                deleteOrganization(organization.id)
            }
        }

        @Test
        fun `delete root user`() {
            testApplication {
                environment {
                    config = ApplicationConfig("application-custom.conf")
                }
                val (organizationResponse, _) = createOrganization()
                val organization = organizationResponse.organization
                val rootUserToken = organizationResponse.rootUserToken

                val username = organizationResponse.organization.rootUser.username

                // Delete root user
                val response =
                    client.delete(
                        "/organizations/${organization.id}/users/$username",
                    ) {
                        header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                        header(HttpHeaders.Authorization, "Bearer $rootUserToken")
                    }
                assertEquals(HttpStatusCode.BadRequest, response.status)
                deleteOrganization(organization.id)
            }
        }
    }

    @Nested
    @DisplayName("List user API tests")
    inner class ListUserTest {
        @Test
        fun `list users`() {
            val testEmail = "test-user-email" + IdGenerator.randomId() + "@hypto.in"
            val createUserRequest1 =
                CreateUserRequest(
                    preferredUsername = "testUserName",
                    name = "lorem ipsum",
                    password = "testPassword@Hash1",
                    email = testEmail,
                    status = CreateUserRequest.Status.enabled,
                    phone = "+919626012778",
                    loginAccess = true,
                )
            val createUserRequest2 =
                CreateUserRequest(
                    preferredUsername = "testUserName2",
                    name = "lorem ipsum",
                    password = "testPassword@Hash2",
                    email = testEmail,
                    status = CreateUserRequest.Status.enabled,
                    phone = "+919626012778",
                    loginAccess = true,
                )
            testApplication {
                environment {
                    config = ApplicationConfig("application-custom.conf")
                }
                val (organizationResponse, _) = createOrganization()
                val organization = organizationResponse.organization
                val rootUserToken = organizationResponse.rootUserToken
                createResource(organization.id, rootUserToken)

                // Create user1
                client.post("/organizations/${organization.id}/users") {
                    header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    header(HttpHeaders.Authorization, "Bearer $rootUserToken")
                    setBody(gson.toJson(createUserRequest1))
                }

                // Create user2
                client.post("/organizations/${organization.id}/users") {
                    header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    header(HttpHeaders.Authorization, "Bearer $rootUserToken")
                    setBody(gson.toJson(createUserRequest2))
                }

                // List users
                val listUsersResponse =
                    client.get("/organizations/${organization.id}/users") {
                        header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                        header(HttpHeaders.Authorization, "Bearer $rootUserToken")
                    }
                assertEquals(HttpStatusCode.OK, listUsersResponse.status)
                assertEquals(
                    ContentType.Application.Json,
                    listUsersResponse.contentType(),
                )

                val responseBody = gson.fromJson(listUsersResponse.bodyAsText(), UserPaginatedResponse::class.java)
                assertEquals(responseBody.data!!.size, 2)
                deleteOrganization(organization.id)
            }
        }
    }

    @Nested
    @DisplayName("Update user API tests")
    inner class UpdateUserTest {
        @Test
        fun `update user`() {
            testApplication {
                environment {
                    config = ApplicationConfig("application-custom.conf")
                }
                val (organizationResponse, _) = createOrganization()
                val organization = organizationResponse.organization
                val rootUserToken = organizationResponse.rootUserToken
                val testEmail = "test-user-email" + IdGenerator.randomId() + "@hypto.in"

                val createUserRequest =
                    CreateUserRequest(
                        preferredUsername = "testUserName",
                        name = "lorem ipsum",
                        password = "testPassword@Hash1",
                        email = testEmail,
                        status = CreateUserRequest.Status.enabled,
                        phone = "+919626012778",
                        verified = false,
                        loginAccess = true,
                    )

                // Create user1
                val (user1, _) =
                    createUser(
                        orgId = organization.id,
                        bearerToken = rootUserToken,
                        createUserRequest = createUserRequest,
                    )

                val updateUserRequest =
                    UpdateUserRequest(
                        name = "name updated",
                        phone = "+911234567890",
                        status = UpdateUserRequest.Status.enabled,
                        verified = true,
                    )

                val response =
                    client.patch(
                        "/organizations/${organization.id}/users/${user1.username}",
                    ) {
                        header(HttpHeaders.Authorization, "Bearer $rootUserToken")
                        header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                        setBody(gson.toJson(updateUserRequest))
                    }
                assertEquals(HttpStatusCode.OK, response.status)
                assertEquals(
                    ContentType.Application.Json,
                    response.contentType(),
                )

                deleteOrganization(organization.id)
            }
        }
    }

    @Nested
    @DisplayName("Change user password API tests")
    inner class ChangeUserPasswordTest {
        @Test
        fun `change root user password - success`() {
            testApplication {
                environment {
                    config = ApplicationConfig("application-custom.conf")
                }
                val (organizationResponse, rootUser) = createOrganization()
                val organization = organizationResponse.organization
                val rootUserToken = organizationResponse.rootUserToken
                val username = organizationResponse.organization.rootUser.username

                val changePasswordRequest =
                    ChangeUserPasswordRequest(
                        oldPassword = "testPassword@Hash1",
                        newPassword = "testPassword@Hash2",
                    )
                val response =
                    client.post(
                        "/organizations/${organization.id}/users/$username/change_password",
                    ) {
                        header(HttpHeaders.Authorization, "Bearer $rootUserToken")
                        header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                        setBody(gson.toJson(changePasswordRequest))
                    }
                assertEquals(HttpStatusCode.OK, response.status)
                assertEquals(
                    ContentType.Application.Json,
                    response.contentType(),
                )
                deleteOrganization(organization.id)
            }
        }

        @Test
        fun `change password with wrong old password - failure`() {
            testApplication {
                environment {
                    config = ApplicationConfig("application-custom.conf")
                }
                val (organizationResponse, rootUser) = createOrganization()
                val organization = organizationResponse.organization
                val rootUserToken = organizationResponse.rootUserToken
                val username = organizationResponse.organization.rootUser.username

                coEvery {
                    cognitoClient.adminInitiateAuth(any<AdminInitiateAuthRequest>())
                } throws NotAuthorizedException.builder().message("Incorrect username or password").build()

                val changePasswordRequest =
                    ChangeUserPasswordRequest(
                        oldPassword = "testPassword@Hash3",
                        newPassword = "testPassword@Hash2",
                    )
                val response =
                    client.post(
                        "/organizations/${organization.id}/users/$username/change_password",
                    ) {
                        header(HttpHeaders.Authorization, "Bearer $rootUserToken")
                        header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                        setBody(gson.toJson(changePasswordRequest))
                    }
                assertEquals(HttpStatusCode.Unauthorized, response.status)
                assertEquals(
                    ContentType.Application.Json,
                    response.contentType(),
                )
                deleteOrganization(organization.id)
            }
        }

        @Test
        fun `user to change password on their own with permission - success`() {
            testApplication {
                environment {
                    config = ApplicationConfig("application-custom.conf")
                }
                val (organizationResponse, _) = createOrganization()
                val organization = organizationResponse.organization
                val rootUserToken = organizationResponse.rootUserToken

                val createUser1Request =
                    CreateUserRequest(
                        preferredUsername = "testUserName1",
                        name = "lorem ipsum",
                        password = "testPassword@Hash1",
                        email = "test-user-email1" + IdGenerator.randomId() + "@iam.in",
                        status = CreateUserRequest.Status.enabled,
                        phone = "+919626012778",
                        verified = true,
                        loginAccess = true,
                    )

                val (user1, credential) =
                    createUser(
                        organization.id,
                        rootUserToken,
                        createUser1Request,
                    )

                createAndAttachPolicy(
                    orgId = organization.id,
                    username = user1.username,
                    bearerToken = rootUserToken,
                    policyName = "user1-policy",
                    subOrgName = null,
                    resourceName = IamResources.USER,
                    actionName = "changePassword",
                    resourceInstance = user1.username,
                )

                val changePasswordRequest =
                    ChangeUserPasswordRequest(
                        oldPassword = "testPassword@Hash1",
                        newPassword = "testPassword@Hash2",
                    )
                val response =
                    client.post(
                        "/organizations/${organization.id}/users/${user1.username}/change_password",
                    ) {
                        header(HttpHeaders.Authorization, "Bearer ${credential.secret}")
                        header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                        setBody(gson.toJson(changePasswordRequest))
                    }
                assertEquals(HttpStatusCode.OK, response.status)
                assertEquals(
                    ContentType.Application.Json,
                    response.contentType(),
                )
                deleteOrganization(organization.id)
            }
        }

        @Test
        fun `change password of different user without permission - failure`() {
            testApplication {
                environment {
                    config = ApplicationConfig("application-custom.conf")
                }
                val (organizationResponse, _) = createOrganization()
                val organization = organizationResponse.organization
                val rootUserToken = organizationResponse.rootUserToken

                val createUser1Request =
                    CreateUserRequest(
                        preferredUsername = "testUserName1",
                        name = "lorem ipsum",
                        password = "testPassword@Hash1",
                        email = "test-user-email1" + IdGenerator.randomId() + "@iam.in",
                        status = CreateUserRequest.Status.enabled,
                        phone = "+919626012778",
                        verified = true,
                        loginAccess = true,
                    )

                val createUser2Request =
                    CreateUserRequest(
                        preferredUsername = "testUserName2",
                        name = "lorem ipsum",
                        password = "testPassword@Hash2",
                        email = "test-user-email" + IdGenerator.randomId() + "@iam.in",
                        status = CreateUserRequest.Status.enabled,
                        phone = "+919626012778",
                        verified = true,
                        loginAccess = true,
                    )
                val (user1, _) =
                    createUser(
                        organization.id,
                        rootUserToken,
                        createUser1Request,
                    )
                val (user2, credential) =
                    createUser(
                        organization.id,
                        rootUserToken,
                        createUser2Request,
                    )

                createAndAttachPolicy(
                    orgId = organization.id,
                    username = user2.username,
                    bearerToken = rootUserToken,
                    policyName = "user2-policy",
                    subOrgName = null,
                    resourceName = IamResources.USER,
                    actionName = "changePassword",
                    resourceInstance = user2.username,
                )

                val changePasswordRequest =
                    ChangeUserPasswordRequest(
                        oldPassword = "testPassword@Hash1",
                        newPassword = "testPassword@Hash2",
                    )
                val response =
                    client.post(
                        "/organizations/${organization.id}/users/${user1.username}/change_password",
                    ) {
                        header(HttpHeaders.Authorization, "Bearer ${credential.secret}")
                        header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                        setBody(gson.toJson(changePasswordRequest))
                    }
                assertEquals(HttpStatusCode.Forbidden, response.status)
                deleteOrganization(organization.id)
            }
        }

        @Test
        fun `generate token after changing password - success`() {
            testApplication {
                environment {
                    config = ApplicationConfig("application-custom.conf")
                }
                val (organizationResponse, rootUser) = createOrganization()
                val organization = organizationResponse.organization
                val rootUserToken = organizationResponse.rootUserToken
                val username = organizationResponse.organization.rootUser.username

                val changePasswordRequest =
                    ChangeUserPasswordRequest(
                        oldPassword = "testPassword@Hash1",
                        newPassword = "testPassword@Hash2",
                    )
                val response =
                    client.post(
                        "/organizations/${organization.id}/users/$username/change_password",
                    ) {
                        header(HttpHeaders.Authorization, "Bearer $rootUserToken")
                        header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                        setBody(gson.toJson(changePasswordRequest))
                    }
                assertEquals(HttpStatusCode.OK, response.status)
                assertEquals(
                    ContentType.Application.Json,
                    response.contentType(),
                )

                val authString = "${rootUser.email}:${changePasswordRequest.newPassword}"
                val authHeader = "Basic ${Base64.getEncoder().encodeToString(authString.encodeToByteArray())}"

                val tokenResponse =
                    client.post(
                        "/organizations/${organization.id}/token",
                    ) {
                        header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                        header(
                            HttpHeaders.Authorization,
                            authHeader,
                        )
                    }

                assertEquals(HttpStatusCode.OK, tokenResponse.status)
                assertEquals(
                    ContentType.Application.Json,
                    tokenResponse.contentType(),
                )
                deleteOrganization(organization.id)
            }
        }
    }

    @Nested
    @DisplayName("Reset user password API tests")
    inner class ResetUserPasswordTest {
        @Test
        fun `reset Password - success`() {
            testApplication {
                environment {
                    config = ApplicationConfig("application-custom.conf")
                }
                val (organizationResponse, createdUser) = createOrganization()
                val organizationId = organizationResponse.organization.id
                val testPasscode = "testPasscode"

                val listUsersResponse =
                    ListUsersResponse.builder().users(
                        listOf(
                            UserType.builder().username(organizationResponse.organization.rootUser.username)
                                .enabled(true).attributes(
                                    listOf(
                                        AttributeType.builder().name(CognitoConstants.ATTRIBUTE_NAME)
                                            .value("test name")
                                            .build(),
                                        AttributeType.builder().name(CognitoConstants.ATTRIBUTE_EMAIL)
                                            .value(createdUser.email)
                                            .build(),
                                        AttributeType.builder().name(CognitoConstants.ATTRIBUTE_PHONE)
                                            .value(createdUser.phone)
                                            .build(),
                                        AttributeType.builder().name(CognitoConstants.ATTRIBUTE_EMAIL_VERIFIED)
                                            .value("true")
                                            .build(),
                                        AttributeType.builder().name(
                                            CognitoConstants.ATTRIBUTE_PREFIX_CUSTOM +
                                                CognitoConstants.ATTRIBUTE_CREATED_BY,
                                        ).value("iam-system").build(),
                                    ),
                                ).userCreateDate(Instant.now()).build(),
                        ),
                    ).build()
                coEvery {
                    cognitoClient.listUsers(any<ListUsersRequest>())
                } returns listUsersResponse

                client.post("/verifyEmail") {
                    header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    setBody(
                        gson.toJson(
                            VerifyEmailRequest(
                                email = createdUser.email,
                                purpose = VerifyEmailRequest.Purpose.reset,
                                organizationId = organizationId,
                            ),
                        ),
                    )
                }

                val resetPasswordResponse =
                    client.post(
                        "/organizations/$organizationId/users/resetPassword",
                    ) {
                        header("X-Api-Key", testPasscode)
                        header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                        setBody(
                            gson.toJson(
                                ResetPasswordRequest(email = createdUser.email, password = "testPassword@123"),
                            ),
                        )
                    }
                assertEquals(HttpStatusCode.OK, resetPasswordResponse.status)
                assertEquals(
                    ContentType.Application.Json,
                    resetPasswordResponse.contentType(),
                )
                val response = gson.fromJson(resetPasswordResponse.bodyAsText(), BaseSuccessResponse::class.java)
                assertTrue(response.success)

                deleteOrganization(organizationId)
            }
        }
    }

    @Nested
    @DisplayName("Attach policy to user API tests")
    inner class UserAttachPolicyTest {
        @Test
        fun `user to attach policy to a different user with permission - success`() {
            testApplication {
                environment {
                    config = ApplicationConfig("application-custom.conf")
                }
                val (organizationResponse, _) = createOrganization()
                val organization = organizationResponse.organization
                val rootUserToken = organizationResponse.rootUserToken

                val createUser1Request =
                    CreateUserRequest(
                        preferredUsername = "testUserName1",
                        name = "lorem ipsum",
                        password = "testPassword@Hash1",
                        email = "test-user-email" + IdGenerator.randomId() + "@iam.in",
                        status = CreateUserRequest.Status.enabled,
                        phone = "+919999999999",
                        verified = true,
                        loginAccess = true,
                    )

                val (user1, _) =
                    createUser(
                        organization.id,
                        rootUserToken,
                        createUser1Request,
                    )
                val createUser2Request =
                    CreateUserRequest(
                        preferredUsername = "testUserName2",
                        name = "lorem ipsum",
                        password = "testPassword@Hash2",
                        email = "test-user-email" + IdGenerator.randomId() + "@iam.in",
                        status = CreateUserRequest.Status.enabled,
                        phone = "+919999999999",
                        verified = true,
                        loginAccess = true,
                    )
                val (user2, credential) =
                    createUser(
                        organization.id,
                        rootUserToken,
                        createUser2Request,
                    )

                createAndAttachPolicy(
                    orgId = organization.id,
                    username = user2.username,
                    bearerToken = rootUserToken,
                    policyName = "test-policy",
                    subOrgName = null,
                    resourceName = IamResources.USER,
                    actionName = "attachPolicies",
                    resourceInstance = user1.username,
                )

                val samplePolicy =
                    createAndAttachPolicy(
                        orgId = organization.id,
                        username = null,
                        bearerToken = rootUserToken,
                        policyName = "sample-policy",
                        subOrgName = null,
                        resourceName = "sample-resource",
                        actionName = "sample-action",
                        resourceInstance = "instanceId",
                    )
                val response =
                    client.patch(
                        "/organizations/${organization.id}/users/${user1.username}/attach_policies",
                    ) {
                        header(HttpHeaders.Authorization, "Bearer ${credential.secret}")
                        header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                        setBody(gson.toJson(PolicyAssociationRequest(listOf(samplePolicy.hrn))))
                    }
                assertEquals(HttpStatusCode.OK, response.status)
                assertEquals(
                    ContentType.Application.Json,
                    response.contentType(),
                )
                deleteOrganization(organization.id)
            }
        }

        @Test
        fun `user to attach policies to a different user without permission - failure`() {
            testApplication {
                environment {
                    config = ApplicationConfig("application-custom.conf")
                }
                val (organizationResponse, _) = createOrganization()
                val organization = organizationResponse.organization
                val rootUserToken = organizationResponse.rootUserToken

                val createUser1Request =
                    CreateUserRequest(
                        preferredUsername = "testUserName1",
                        name = "lorem ipsum",
                        password = "testPassword@Hash1",
                        email = "test-user-email" + IdGenerator.randomId() + "@iam.in",
                        status = CreateUserRequest.Status.enabled,
                        phone = "+919999999999",
                        verified = true,
                        loginAccess = true,
                    )

                val (user1, _) =
                    createUser(
                        organization.id,
                        rootUserToken,
                        createUser1Request,
                    )
                val createUser2Request =
                    CreateUserRequest(
                        preferredUsername = "testUserName2",
                        name = "lorem ipsum",
                        password = "testPassword@Hash2",
                        email = "test-user-email" + IdGenerator.randomId() + "@iam.in",
                        status = CreateUserRequest.Status.enabled,
                        phone = "+919999999999",
                        verified = true,
                        loginAccess = true,
                    )
                val (user2, credential) =
                    createUser(
                        organization.id,
                        rootUserToken,
                        createUser2Request,
                    )
                createAndAttachPolicy(
                    orgId = organization.id,
                    username = user2.username,
                    bearerToken = rootUserToken,
                    policyName = "test-policy",
                    subOrgName = null,
                    resourceName = IamResources.USER,
                    actionName = "attachPolicies",
                    resourceInstance = user2.username,
                )

                val samplePolicy =
                    createAndAttachPolicy(
                        orgId = organization.id,
                        username = null,
                        bearerToken = rootUserToken,
                        policyName = "sample-policy",
                        subOrgName = null,
                        resourceName = "sample-resource",
                        actionName = "sample-action",
                        resourceInstance = "instanceId",
                    )

                val response =
                    client.patch(
                        "/organizations/${organization.id}/users/${user1.username}/attach_policies",
                    ) {
                        header(HttpHeaders.Authorization, "Bearer ${credential.secret}")
                        header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                        setBody(gson.toJson(PolicyAssociationRequest(listOf(samplePolicy.hrn))))
                    }

                assertEquals(HttpStatusCode.Forbidden, response.status)
                assertEquals(
                    ContentType.Application.Json,
                    response.contentType(),
                )
                deleteOrganization(organization.id)
            }
        }
    }
}
