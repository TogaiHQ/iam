/**
* Hypto IAM
* APIs for Hypto IAM Service.
*
* OpenAPI spec version: 1.0.0
* Contact: engineering@hypto.in
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/swagger-api/swagger-codegen.git
* Do not edit the class manually.
*/package com.hypto.iam.server.models


/**
 * Payload to update credential * @param validUntil  * @param status */
data class UpdateCredentialRequest (    val validUntil: kotlin.String? = null,    val status: UpdateCredentialRequest.Status? = null
) {
    /**
    * 
    * Values: ACTIVE,INACTIVE
    */
    enum class Status(val value: kotlin.String){
        ACTIVE("active"),
        INACTIVE("inactive");
    }
}
