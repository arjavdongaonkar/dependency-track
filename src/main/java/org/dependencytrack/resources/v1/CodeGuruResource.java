/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.resources.v1;

import alpine.event.framework.Event;
import alpine.server.auth.PermissionRequired;
import alpine.server.resources.AlpineResource;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.event.SASTUploadEvent;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectCollectionLogic;
import org.dependencytrack.model.Tag;
import org.dependencytrack.persistence.QueryManager;
import org.glassfish.jersey.media.multipart.BodyPartEntity;
import org.glassfish.jersey.media.multipart.FormDataBodyPart;
import org.glassfish.jersey.media.multipart.FormDataParam;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.function.Predicate.not;

/**
 * JAX-RS resources for processing AWS CodeGuru SAST findings.
 *
 * @author Your Name
 * @since 1.0.0
 */
@Path("/v1/codeguru")
@io.swagger.v3.oas.annotations.tags.Tag(name = "codeguru")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class CodeGuruResource extends AlpineResource {

    private static final Logger LOGGER = LoggerFactory.getLogger(CodeGuruResource.class);

    @POST
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Upload AWS CodeGuru SAST findings",
            description = """
                    <p>
                        Uploads AWS CodeGuru SAST findings in JSON format.
                        Expects a valid project UUID. If a UUID is not specified,
                        then the <code>projectName</code> and <code>projectVersion</code> must be specified.
                        Optionally, if <code>autoCreate</code> is specified and <code>true</code> and the project does not exist,
                        the project will be created.
                    </p>
                    """,
            operationId = "UploadCodeGuruFindings"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "CodeGuru findings upload successful"),
            @ApiResponse(responseCode = "400", description = "Invalid CodeGuru findings format"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Access to the specified project is forbidden"),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_ANALYSIS)
    public Response uploadCodeGuruFindings(
            @FormDataParam("project") String projectUuid,
            @DefaultValue("false") @FormDataParam("autoCreate") boolean autoCreate,
            @FormDataParam("projectName") String projectName,
            @FormDataParam("projectVersion") String projectVersion,
            @FormDataParam("projectTags") String projectTags,
            @Parameter(schema = @Schema(type = "string")) @FormDataParam("findings") final List<FormDataBodyPart> findingsParts
    ) {

        final List<org.dependencytrack.model.Tag> requestTags = (projectTags != null && !projectTags.isBlank())
                ? Arrays.stream(projectTags.split(",")).map(String::trim).filter(not(String::isEmpty)).map(org.dependencytrack.model.Tag::new).toList()
                : null;

        if (findingsParts == null || findingsParts.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("No CodeGuru findings file provided")
                    .build();
        }

        if (projectUuid != null) {
            try (QueryManager qm = new QueryManager()) {
                final Project project = qm.getObjectByUuid(Project.class, projectUuid);
                return processCodeGuruFindings(qm, project, findingsParts, requestTags);
            }
        } else {
            try (QueryManager qm = new QueryManager()) {
                final String trimmedProjectName = StringUtils.trimToNull(projectName);
                final String trimmedProjectVersion = StringUtils.trimToNull(projectVersion);

                if (trimmedProjectName == null || trimmedProjectVersion == null) {
                    return Response.status(Response.Status.BAD_REQUEST)
                            .entity("Project UUID or both projectName and projectVersion must be specified")
                            .build();
                }

                Project project = qm.getProject(trimmedProjectName, trimmedProjectVersion);

                if (project == null && autoCreate) {
                    if (hasPermission(Permissions.Constants.PORTFOLIO_MANAGEMENT) ||
                            hasPermission(Permissions.Constants.PROJECT_CREATION_UPLOAD)) {

                        project = qm.createProject(trimmedProjectName, null, trimmedProjectVersion,
                                null, null, null, true, false, true);
                        Principal principal = getPrincipal();
                        qm.updateNewProjectACL(project, principal);
                    } else {
                        return Response.status(Response.Status.UNAUTHORIZED)
                                .entity("The principal does not have permission to create project")
                                .build();
                    }
                }

                return processCodeGuruFindings(qm, project, findingsParts, requestTags);
            }
        }
    }

    /**
     * Common logic that processes CodeGuru findings given a project and list of multi-part form objects.
     */
    private Response processCodeGuruFindings(QueryManager qm, Project project, List<FormDataBodyPart> findingsParts, List<Tag> requestTags) {
        if (project == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("The project could not be found")
                    .build();
        }

        if (!qm.hasAccess(super.getPrincipal(), project)) {
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("Access to the specified project is forbidden")
                    .build();
        }

        if (!project.getCollectionLogic().equals(ProjectCollectionLogic.NONE)) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("CodeGuru findings cannot be uploaded to collection project")
                    .build();
        }

        maybeBindTags(qm, project, requestTags);

        for (final FormDataBodyPart findingsPart : findingsParts) {
            final BodyPartEntity bodyPartEntity = (BodyPartEntity) findingsPart.getEntity();

            try (InputStream in = bodyPartEntity.getInputStream()) {
                final byte[] content = IOUtils.toByteArray(in);

                // Dispatch the CodeGuru analysis event
                final SASTUploadEvent analysisEvent =
                        new SASTUploadEvent(qm.getPersistenceManager().detachCopy(project), content);
                Event.dispatch(analysisEvent);

                return Response.ok(Collections.singletonMap("token", analysisEvent.getChainIdentifier())).build();

            } catch (IOException e) {
                LOGGER.error("Failed to read CodeGuru findings file", e);
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("Failed to read CodeGuru findings file")
                        .build();
            }
        }

        return Response.ok().build();
    }

    private void maybeBindTags(final QueryManager qm, final Project project, final List<Tag> tags) {
        if (tags == null) {
            return;
        }

        // If the principal has the PROJECT_CREATION_UPLOAD permission,
        // and a new project was created as part of this upload,
        // the project might already have the requested tags.
        final Set<String> existingTagNames = project.getTags() != null
                ? project.getTags().stream().map(Tag::getName).collect(Collectors.toSet())
                : Collections.emptySet();
        final Set<String> requestTagNames = tags.stream().map(Tag::getName).collect(Collectors.toSet());

        if (!Objects.equals(existingTagNames, requestTagNames)
                && !hasPermission(Permissions.Constants.PORTFOLIO_MANAGEMENT)) {
            // Most CI integrations will use API keys with PROJECT_CREATION_UPLOAD permission,
            // but not PORTFOLIO_MANAGEMENT permission. They will not send different upload requests
            // though, after a project was first created. Failing the request would break those
            // integrations. Log a warning instead.
            LOGGER.warn("""
                    Project tags were provided as part of the BOM upload request, \
                    but the authenticated principal is missing the %s permission; \
                    Tags will not be modified""".formatted(Permissions.Constants.PORTFOLIO_MANAGEMENT));
            return;
        }

        final Set<Tag> resolvedTags = qm.resolveTags(tags);
        qm.bind(project, resolvedTags);
    }

}
