package com.hypto.iam.server.apis

import com.google.gson.Gson
import com.hypto.iam.server.models.SsoLoginRequest
import com.hypto.iam.server.service.SsoLoginService
import com.hypto.iam.server.validators.validate
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.call
import io.ktor.server.request.receive
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.post
import org.koin.ktor.ext.inject

fun Route.ssoLoginApi() {
    val ssoLoginService: SsoLoginService by inject()
    val gson: Gson by inject()
    post("/sso_login") {
        val request = call.receive<SsoLoginRequest>().validate()
        val response = ssoLoginService.getAuthUrlForDomain(request)
        call.respondText(
            text = gson.toJson(response),
            contentType = ContentType.Application.Json,
            status = HttpStatusCode.OK,
        )
    }
}
