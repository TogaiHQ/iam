package com.hypto.iam.server

import com.codahale.metrics.Slf4jReporter
import com.typesafe.config.ConfigFactory
import io.ktor.application.Application
import io.ktor.application.ApplicationStopping
import io.ktor.application.install
import io.ktor.application.log
import io.ktor.auth.*
import io.ktor.client.HttpClient
import io.ktor.client.engine.apache.Apache
import io.ktor.config.HoconApplicationConfig
import io.ktor.features.AutoHeadResponse
import io.ktor.features.Compression
import io.ktor.features.ContentNegotiation
import io.ktor.features.DefaultHeaders
import io.ktor.features.HSTS
import io.ktor.gson.GsonConverter
import io.ktor.http.ContentType
import io.ktor.locations.KtorExperimentalLocationsAPI
import io.ktor.locations.Locations
import io.ktor.routing.Routing
import java.util.concurrent.TimeUnit
import io.ktor.util.KtorExperimentalAPI
import io.ktor.metrics.dropwizard.DropwizardMetrics
import com.hypto.iam.server.apis.ActionApi
import com.hypto.iam.server.apis.CredentialApi
import com.hypto.iam.server.apis.OrganizationApi
import com.hypto.iam.server.apis.PolicyApi
import com.hypto.iam.server.apis.ResourceTypeApi
import com.hypto.iam.server.apis.TokenApi
import com.hypto.iam.server.apis.UsersApi
import com.hypto.iam.server.service.DatabaseFactory

@KtorExperimentalAPI
internal val settings = HoconApplicationConfig(ConfigFactory.defaultApplication(HTTP::class.java.classLoader))

object HTTP {
    val client = HttpClient(Apache)
}

@KtorExperimentalAPI
@KtorExperimentalLocationsAPI
fun Application.main() {
    install(DefaultHeaders)
    install(DropwizardMetrics) {
        val reporter = Slf4jReporter.forRegistry(registry)
                .outputTo(log)
                .convertRatesTo(TimeUnit.SECONDS)
                .convertDurationsTo(TimeUnit.MILLISECONDS)
                .build()
        reporter.start(10, TimeUnit.SECONDS)
    }
    install(ContentNegotiation) {
        register(ContentType.Application.Json, GsonConverter())
    }
    install(AutoHeadResponse) // see http://ktor.io/features/autoheadresponse.html
    install(HSTS, ApplicationHstsConfiguration()) // see http://ktor.io/features/hsts.html
    install(Compression, ApplicationCompressionConfiguration()) // see http://ktor.io/features/compression.html
    install(Locations) // see http://ktor.io/features/locations.html
    install(Authentication) {
//        basic {  }
//        bearer {
//            refreshTokensFun = { BearerTokens("valid", "refresh") }
//            loadTokensFun = { BearerTokens("invalid", "refresh") }
//        }
    }

    DatabaseFactory.connectAndMigrate()

    install(Routing) {
        ActionApi()
        CredentialApi()
        OrganizationApi()
        PolicyApi()
        ResourceTypeApi()
        TokenApi()
        UsersApi()
    }


    environment.monitor.subscribe(ApplicationStopping)
    {
        HTTP.client.close()
    }
}
