/*
 * Copyright 2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.samples.petclinic.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Collections;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;

/**
 * Java config for springdoc-openapi API documentation library
 *
 * @author Vitaliy Fedoriv
 */
@Configuration
public class SwaggerConfig {

    private static final String BEARER_SCHEME = "bearer-jwt";

    @Bean
    OpenAPI customOpenAPI() {
        return new OpenAPI()
            .components(new Components()
                .addSecuritySchemes(BEARER_SCHEME, new SecurityScheme()
                    .type(SecurityScheme.Type.HTTP)
                    .scheme("bearer")
                    .bearerFormat("JWT")))
            .addSecurityItem(new SecurityRequirement().addList(BEARER_SCHEME))
            .info(new Info()
                .title("omar-petclinic API documentation")
                .version("1.0")
                .termsOfService("https://github.com/spring-petclinic/spring-petclinic-rest/blob/master/terms.txt")
                .description(
                    "REST API of omar-petclinic, based on the Spring Petclinic backend. " +
                        "Every endpoint requires a Keycloak access token (realm omar-petclinic) sent as a Bearer token.")
                .license(swaggerLicense())
                .contact(swaggerContact()));
    }

    private Contact swaggerContact() {
        Contact petclinicContact = new Contact();
        petclinicContact.setName("Vitaliy Fedoriv");
        petclinicContact.setEmail("vitaliy.fedoriv@gmail.com");
        petclinicContact.setUrl("https://github.com/spring-petclinic/spring-petclinic-rest");
        return petclinicContact;
    }

    private License swaggerLicense() {
        License petClinicLicense = new License();
        petClinicLicense.setName("Apache 2.0");
        petClinicLicense.setUrl("http://www.apache.org/licenses/LICENSE-2.0");
        petClinicLicense.setExtensions(Collections.emptyMap());
        return petClinicLicense;
    }

}
