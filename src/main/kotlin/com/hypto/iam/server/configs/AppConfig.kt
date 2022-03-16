package com.hypto.iam.server.configs

import com.sksamuel.hoplite.ConfigLoader

class AppConfig {
    /*
    Environment variables should be in Snake case.
    E.g. env, token_validity

    Nested variables should be defined with the data class name followed by 2 underscores and then the variable name
    {data_class_name}__{variable_name}
    E.g. For Database - database__host, database__port, database__username, database__password
     */

    data class Database(val host: String, val port: Int, val username: String, val password: String) {
        val jdbcUrl: String
            get() = "jdbc:postgresql://$host:$port/iam"
    }

    data class App(val env: String, val jwtTokenValidity: Long) {
        val isDevelopment: Boolean
            get() = env == "development"
    }

    // Get NewRelic licence key from https://one.newrelic.com/admin-portal/api-keys/home
    data class Newrelic(val apiKey: String, val publishInterval: Long)

    data class Config(val app: App, val database: Database, val newrelic: Newrelic)
    val configuration: Config = ConfigLoader().loadConfigOrThrow("/default_config.json")
}