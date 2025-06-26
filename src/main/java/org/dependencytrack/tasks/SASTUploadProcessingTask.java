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
package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;
import org.datanucleus.flush.FlushMode;
import org.dependencytrack.event.PolicyEvaluationEvent;
import org.dependencytrack.event.SASTUploadEvent;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisComment;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.ComponentProperty;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.ExternalReference;
import org.dependencytrack.model.FindingAttribution;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.ViolationAnalysisComment;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.awscodeguru.AWSCodeGuruFinding;
import org.dependencytrack.parser.awscodeguru.CodeGuruResponse;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.listener.IndexingInstanceLifecycleListener;
import org.slf4j.MDC;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static alpine.model.IConfigProperty.PropertyType.STRING;
import static org.apache.commons.lang3.time.DurationFormatUtils.formatDurationHMS;
import static org.datanucleus.FetchPlan.FETCH_SIZE_GREEDY;
import static org.datanucleus.PropertyNames.PROPERTY_FLUSH_MODE;
import static org.datanucleus.PropertyNames.PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT;
import static org.dependencytrack.common.MdcKeys.MDC_EVENT_TOKEN;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_NAME;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_VERSION;
import static org.dependencytrack.model.Vulnerability.Source.AWSCODEGURU;
import static org.dependencytrack.tasks.scanners.AnalyzerIdentity.AWS_CODEGURU_ANALYZER;
import static org.dependencytrack.util.LockUtil.getLockForProjectAndNamespace;
import static org.dependencytrack.util.PersistenceUtil.applyIfChanged;
import static org.dependencytrack.util.PersistenceUtil.assertPersistent;

public class SASTUploadProcessingTask implements Subscriber {

    private static final class Context {
        private final UUID token;
        private final Project project;
        private final long startTimeNs;

        private Context(final UUID token, final Project project) {
            this.token = token;
            this.project = project;
            this.startTimeNs = System.nanoTime();
        }
    }

    private static final Logger LOGGER = Logger.getLogger(SASTUploadProcessingTask.class);

    private final List<Event> eventsToDispatch = new ArrayList<>();

    @Override
    public void inform(final Event e) {
        if (!(e instanceof final SASTUploadEvent event)) {
            return;
        }
        final var ctx = new Context(event.getChainIdentifier(), event.getProject());
        try (var ignoredMdcProjectUuid = MDC.putCloseable(MDC_PROJECT_UUID, ctx.project.getUuid().toString());
             var ignoredMdcProjectName = MDC.putCloseable(MDC_PROJECT_NAME, ctx.project.getName());
             var ignoredMdcProjectVersion = MDC.putCloseable(MDC_PROJECT_VERSION, ctx.project.getVersion());
             var ignoredMdcCodeGuruUploadToken = MDC.putCloseable(MDC_EVENT_TOKEN, ctx.token.toString())) {
            processEvent(ctx, event);
        }
    }

    private void processEvent(final Context ctx, final SASTUploadEvent event) {
        final List<AWSCodeGuruFinding> codeGuruFindings;
        final CodeGuruResponse codeGuruResponse;
        try {
            final String reportJson = new String(event.getFindingsData(), StandardCharsets.UTF_8);
            codeGuruResponse = parseCodeGuruReport(reportJson);
            codeGuruFindings = codeGuruResponse.getFindings();

        } catch (Exception e) {
            LOGGER.error("Failed to parse CodeGuru report", e);
            return;
        }

        final ReentrantLock lock = getLockForProjectAndNamespace(ctx.project, getClass().getSimpleName());
        try {
            lock.lock();
            processCodeGuruReport(ctx, codeGuruFindings);

            LOGGER.info("Dispatching %d events".formatted(eventsToDispatch.size()));
            eventsToDispatch.forEach(Event::dispatch);
        } catch (RuntimeException e) {
            LOGGER.error("Failed to process CodeGuru report", e);
        } finally {
            lock.unlock();
        }
    }

    private CodeGuruResponse parseCodeGuruReport(final String reportJson) throws Exception {
        final ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(reportJson, CodeGuruResponse.class);
    }

    private void processCodeGuruReport(final Context ctx, final List<AWSCodeGuruFinding> findings) {
        LOGGER.info("Consuming uploaded CodeGuru report");

        List<Component> components = extractComponentsFromFindings(findings);
        final int numComponentsTotal = components.size();

        final var identitiesByPath = new HashMap<String, ComponentIdentity>();
        final var pathsByIdentity = new HashSetValuedHashMap<ComponentIdentity, String>();
        components = components.stream().filter(distinctComponentsByIdentity(identitiesByPath, pathsByIdentity)).toList();

        LOGGER.info("Consumed %d components (%d before de-duplication)".formatted(components.size(), numComponentsTotal));

        final var processedComponents = new ArrayList<Component>(components.size());

        try (final var qm = new QueryManager()) {
            qm.getPersistenceManager().setProperty(PROPERTY_PERSISTENCE_BY_REACHABILITY_AT_COMMIT, "false");
            qm.getPersistenceManager().setProperty(PROPERTY_FLUSH_MODE, FlushMode.MANUAL.name());
            qm.getPersistenceManager().addInstanceLifecycleListener(new IndexingInstanceLifecycleListener(eventsToDispatch::add),
                    Component.class, Vulnerability.class);

            final List<Component> finalComponents = components;
            final List<AWSCodeGuruFinding> finalFindings = findings;

            qm.runInTransaction(() -> {
                try {
                    final Project persistentProject = getProject(ctx, qm);
                    if (persistentProject == null) {
                        throw new IllegalStateException("Project not found for context: " + ctx);
                    }

                    LOGGER.info("Processing %d components".formatted(finalComponents.size()));

                    final Map<ComponentIdentity, Component> persistentComponentsByIdentity =
                            processComponents(qm, persistentProject, finalComponents, identitiesByPath, pathsByIdentity);
                    processedComponents.addAll(persistentComponentsByIdentity.values());

                    LOGGER.info("Processing %d vulnerabilities".formatted(finalFindings.size()));
                    processVulnerabilities(qm, finalFindings, persistentComponentsByIdentity, identitiesByPath);
                    final PolicyEvaluationEvent policyEvaluationEvent =
                            new PolicyEvaluationEvent(processedComponents).project(ctx.project);
                    persistentProject.setLastBomImport(new Date());
                    qm.persist(persistentProject);
                    Event.dispatch(policyEvaluationEvent);
                } catch (Exception e) {
                    LOGGER.error("Error processing CodeGuru report in transaction", e);
                    throw new RuntimeException("Failed to process CodeGuru report", e);
                }
            });
        } catch (Exception e) {
            LOGGER.error("Error processing CodeGuru report", e);
            throw new RuntimeException("Failed to process CodeGuru report", e);
        }

        final var processingDurationMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - ctx.startTimeNs);
        LOGGER.info("CodeGuru report processed successfully in %s".formatted(formatDurationHMS(processingDurationMs)));
    }

    private Map<ComponentIdentity, Component> processComponents(
            final QueryManager qm,
            final Project project,
            final List<Component> components,
            final Map<String, ComponentIdentity> identitiesByPath,
            final MultiValuedMap<ComponentIdentity, String> pathsByIdentity
    ) {
        assertPersistent(project, "Project must be persistent");

        final List<Component> persistentComponents = getAllComponents(qm, project);
        final Map<ComponentIdentity, Component> persistentComponentByIdentity = persistentComponents.stream()
                .collect(Collectors.toMap(
                        component -> new ComponentIdentity(component, /* excludeUuid */ true),
                        Function.identity(),
                        (previous, duplicate) -> {
                            LOGGER.warn("More than one existing component matches the identity %s; Proceeding with first match, others will be deleted".formatted(new ComponentIdentity(previous, /* excludeUuid */ true)));
                            return previous;
                        }));

        final Set<Long> idsOfComponentsToDelete = persistentComponents.stream()
                .filter(component -> "aws-codeguru".equals(component.getGroup()))
                .map(Component::getId)
                .collect(Collectors.toSet());

        for (final Component component : components) {
            if (component == null) {
                LOGGER.warn("Null component found, skipping");
                continue;
            }

            final var componentIdentity = new ComponentIdentity(component);
            Component persistentComponent = persistentComponentByIdentity.get(componentIdentity);

            if (persistentComponent == null) {
                component.setProject(project);
                persistentComponent = qm.persist(component);
                if (persistentComponent != null) {
                    component.setNew(true); // Transient
                }
            } else {
                persistentComponent.setBomRef(component.getBomRef()); // Transient
                applyIfChanged(persistentComponent, component, Component::getName, persistentComponent::setName);
                applyIfChanged(persistentComponent, component, Component::getGroup, persistentComponent::setGroup);
                applyIfChanged(persistentComponent, component, Component::getVersion, persistentComponent::setVersion);
                applyIfChanged(persistentComponent, component, Component::getDescription, persistentComponent::setDescription);
                applyIfChanged(persistentComponent, component, Component::getClassifier, persistentComponent::setClassifier);

                idsOfComponentsToDelete.remove(persistentComponent.getId());
            }

            if (persistentComponent != null) {
                final var newIdentity = new ComponentIdentity(persistentComponent);
                final String bomRef = persistentComponent.getBomRef();

                if (bomRef != null) {
                    final ComponentIdentity oldIdentity = identitiesByPath.put(bomRef, newIdentity);
                    if (oldIdentity != null) {
                        final Collection<String> paths = pathsByIdentity.get(oldIdentity);
                        if (paths != null) {
                            for (final String path : paths) {
                                identitiesByPath.put(path, newIdentity);
                            }
                        }
                    }
                }
                persistentComponentByIdentity.put(newIdentity, persistentComponent);
            }
        }

        // Remove components that are no longer part of the report
        persistentComponentByIdentity.entrySet().removeIf(entry -> {
            final ComponentIdentity identity = entry.getKey();
            if (identity.getUuid() == null) {
                return true;
            }
            final Component component = entry.getValue();
            return idsOfComponentsToDelete.contains(component.getId());
        });

        qm.getPersistenceManager().flush();
        final long componentsDeleted = deleteComponentsById(qm, idsOfComponentsToDelete);
        if (componentsDeleted > 0) {
            LOGGER.info("Deleted %d obsolete components".formatted(componentsDeleted));
            qm.getPersistenceManager().flush();
        }

        return persistentComponentByIdentity;
    }

    private void processVulnerabilities(
            final QueryManager qm,
            final List<AWSCodeGuruFinding> findings,
            final Map<ComponentIdentity, Component> persistentComponentsByIdentity,
            final Map<String, ComponentIdentity> identitiesByPath
    ) {
        boolean didCreateVulns = false;
        int processedCount = 0;
        int skippedCount = 0;

        for (final AWSCodeGuruFinding finding : findings) {
            if (finding == null || finding.getVulnerability() == null ||
                    finding.getVulnerability().getFilePath() == null) {
                LOGGER.warn("Invalid finding structure, skipping");
                skippedCount++;
                continue;
            }

            final String filePath = finding.getVulnerability().getFilePath().getPath();
            if (filePath == null || filePath.trim().isEmpty()) {
                LOGGER.warn("Empty file path in finding, skipping");
                skippedCount++;
                continue;
            }

            final ComponentIdentity componentIdentity = identitiesByPath.get(filePath);
            if (componentIdentity == null) {
                LOGGER.warn("Could not find component for file path: %s".formatted(filePath));
                skippedCount++;
                continue;
            }

            final Component persistentComponent = persistentComponentsByIdentity.get(componentIdentity);
            if (persistentComponent == null) {
                LOGGER.warn("Could not find persistent component for identity: %s".formatted(componentIdentity));
                skippedCount++;
                continue;
            }
            // Compute MD5 hash from filePath.path + codeSnippet[startLine].content
            final String vulnId = computeVulnHash(finding);
            if (vulnId.trim().isEmpty()) {
                LOGGER.warn("Invalid vulnerability ID in finding, skipping");
                skippedCount++;
                continue;
            }

            try {
                // Create or get vulnerability
                Vulnerability vulnerability = qm.getVulnerabilityByVulnId(AWSCODEGURU, vulnId);

                if (vulnerability == null) {
                    // Create new vulnerability from CodeGuru finding
                    final Vulnerability parsedVulnerability = convertToVulnerability(finding, vulnId);
                    if (parsedVulnerability != null) {
                        vulnerability = qm.createVulnerability(parsedVulnerability, false);
                        qm.getPersistenceManager().flush();
                        didCreateVulns = true;
                        LOGGER.info("Created new vulnerability: %s".formatted(vulnId));
                    } else {
                        LOGGER.warn("Failed to convert finding to vulnerability: %s".formatted(vulnId));
                        skippedCount++;
                        continue;
                    }
                }

                // Associate vulnerability with component
                qm.addVulnerability(vulnerability, persistentComponent, AWS_CODEGURU_ANALYZER, null, createRefId(finding));
                processedCount++;
            } catch (Exception e) {
                LOGGER.error("Error processing vulnerability %s: %s".formatted(vulnId, e.getMessage()));
                skippedCount++;
            }
        }

        if (didCreateVulns) {
            qm.getPersistenceManager().flush();
        }

        LOGGER.info("Processed %d vulnerabilities, skipped %d".formatted(processedCount, skippedCount));
    }

    private String createRefId(AWSCodeGuruFinding finding) {
        String region = System.getenv("AWS_REGION");
        if (region == null || region.isEmpty()) {
            region = "ap-southeast-1";
        }

        String findingId = finding.getId();
        String resourceId = finding.getResource() != null ? finding.getResource().getId() : "unknown-resource";

        return String.format(
                "https://%s.console.aws.amazon.com/codeguru/security/findings/%s/%s?region=%s#tab=findings&status=Open",
                region,
                resourceId,
                findingId,
                region
        );
    }


    private static Predicate<Component> distinctComponentsByIdentity(
            final Map<String, ComponentIdentity> identitiesByPath,
            final MultiValuedMap<ComponentIdentity, String> pathsByIdentity
    ) {
        final var identitiesSeen = new HashSet<ComponentIdentity>();

        return component -> {
            if (component == null) {
                LOGGER.warn("Null component encountered, filtering out");
                return false;
            }

            final var componentIdentity = new ComponentIdentity(component);
            final String bomRef = component.getBomRef();

            if (bomRef == null || bomRef.trim().isEmpty()) {
                LOGGER.warn("Component with empty BOM reference encountered, filtering out");
                return false;
            }

            final boolean isPathUnique = identitiesByPath.putIfAbsent(bomRef, componentIdentity) == null;

            if (!isPathUnique) {
                LOGGER.warn("File path {} is associated with multiple components in the report; File paths should be unique; Please verify the CodeGuru report");
            }

            pathsByIdentity.put(componentIdentity, bomRef);

            final boolean isSeenBefore = !identitiesSeen.add(componentIdentity);
            if (LOGGER.isDebugEnabled() && isSeenBefore) {
                LOGGER.info("Filtering component with file path {} and identity {} due to duplicate identity");
            }

            return !isSeenBefore;
        };
    }

    private Project getProject(final Context ctx, final QueryManager qm) {
        final Query<Project> query = qm.getPersistenceManager().newQuery(Project.class);
        query.setFilter("uuid == :uuid");
        query.setParameters(ctx.project.getUuid());
        final Project persistentProject;
        try {
            persistentProject = query.executeUnique();
        } finally {
            query.closeAll();
        }
        if (persistentProject == null) {
            throw new IllegalStateException("Project does not exist");
        }
        return persistentProject;
    }

    private List<Component> extractComponentsFromFindings(final List<AWSCodeGuruFinding> findings) {
        final Map<String, Component> componentsByPath = new HashMap<>();

        for (final AWSCodeGuruFinding finding : findings) {
            final String filePath = finding.getVulnerability().getFilePath().getPath();
            String fileName = finding.getVulnerability().getFilePath().getName();
            if (!componentsByPath.containsKey(filePath)) {
                final Component component = new Component();
                setComponentAttributes(finding, component, filePath, fileName);
                componentsByPath.put(filePath, component);
            }
        }

        return new ArrayList<>(componentsByPath.values());
    }

    private static void setComponentAttributes(AWSCodeGuruFinding finding, Component component, String filePath, String fileName) {
        component.setName(filePath);
        component.setGroup("aws-codeguru");
        component.setVersion("1.0.0"); // Default version since CodeGuru doesn't provide version info
        component.setClassifier(Classifier.FILE);
        component.setDescription("");
        component.setDescription(String.format("File analyzed by AWS CodeGuru: %s - %s",
                filePath,
                finding.getDetectorName()));
        String purl = String.format("pkg:file/%s@%s",
                filePath.replace("/", "%2F"),
                finding.getGeneratorId());
        component.setPurlCoordinates(purl);
        component.setPurl(purl);
        List<ExternalReference> externalRefs = new ArrayList<>();
        if (finding.getRemediation() != null &&
                finding.getRemediation().getRecommendation() != null &&
                finding.getRemediation().getRecommendation().getURL() != null) {

            ExternalReference remediationRef = new ExternalReference();
            remediationRef.setType(org.cyclonedx.model.ExternalReference.Type.ADVISORIES);
            remediationRef.setUrl(finding.getRemediation().getRecommendation().getURL());
            remediationRef.setComment("AWS CodeGuru remediation guidance");
            externalRefs.add(remediationRef);
        }
        component.setExternalReferences(externalRefs);
        component.setBomRef(filePath);
        List<ComponentProperty> properties = new ArrayList<>();

        ComponentProperty detectorProp = new ComponentProperty();
        detectorProp.setGroupName("codeguru");
        detectorProp.setPropertyType(STRING);
        detectorProp.setPropertyName("detectorId");
        detectorProp.setPropertyValue(finding.getDetectorId());
        properties.add(detectorProp);

        ComponentProperty severityProp = new ComponentProperty();
        severityProp.setGroupName("codeguru");
        severityProp.setPropertyName("severity");
        severityProp.setPropertyType(STRING);
        severityProp.setPropertyValue(finding.getSeverity());
        properties.add(severityProp);

        ComponentProperty ruleProp = new ComponentProperty();
        ruleProp.setGroupName("codeguru");
        ruleProp.setPropertyName("ruleId");
        ruleProp.setPropertyType(STRING);
        ruleProp.setPropertyValue(finding.getRuleId());
        properties.add(ruleProp);

        if (finding.getDetectorTags() != null && !finding.getDetectorTags().isEmpty()) {
            ComponentProperty tagsProp = new ComponentProperty();
            tagsProp.setGroupName("codeguru");
            tagsProp.setPropertyName("tags");
            tagsProp.setPropertyType(STRING);
            tagsProp.setPropertyValue(String.join(",", finding.getDetectorTags()));
            properties.add(tagsProp);
        }

        ComponentProperty resourceProp = new ComponentProperty();
        resourceProp.setGroupName("codeguru");
        resourceProp.setPropertyName("resourceId");
        resourceProp.setPropertyType(STRING);
        resourceProp.setPropertyValue(finding.getResource().getId());
        properties.add(resourceProp);

        component.setProperties(properties);

        if (fileName.contains(".")) {
            component.setExtension(fileName.substring(fileName.lastIndexOf(".") + 1));
        }
        component.setNotes(String.format("CodeGuru Finding: %s\nType: %s\nStatus: %s\nCreated: %s",
                finding.getTitle(),
                finding.getType(),
                finding.getStatus(),
                finding.getCreatedAt()));
    }

    private Vulnerability convertToVulnerability(final AWSCodeGuruFinding finding, String vulnId) {
        Vulnerability vuln = new Vulnerability();

        vuln.setVulnId(vulnId);

        vuln.setSource(AWSCODEGURU);
        vuln.setTitle(finding.getTitle());
        vuln.setFriendlyVulnId("%s (%s)".formatted(finding.getDetectorName(), finding.getDetectorId()));
        vuln.setSubTitle(finding.getId());
        vuln.setDescription(finding.getDescription());
        vuln.setSeverity(convertSeverity(finding.getSeverity()));

        vuln.setCreated(parseCodeGuruDate(finding.getCreatedAt()));
        vuln.setUpdated(parseCodeGuruDate(finding.getUpdatedAt()));

        if (finding.getRemediation() != null && finding.getRemediation().getRecommendation() != null) {
            vuln.setRecommendation(finding.getRemediation().getRecommendation().getText());

            List<String> allReferences = new ArrayList<>();
            if (finding.getRemediation().getRecommendation().getURL() != null) {
                allReferences.add(finding.getRemediation().getRecommendation().getURL());
            }
            if (finding.getVulnerability() != null && finding.getVulnerability().getReferenceUrls() != null) {
                allReferences.addAll(finding.getVulnerability().getReferenceUrls());
            }
            vuln.setReferences(String.join(", ", allReferences));
        }

        if (finding.getVulnerability() != null && finding.getVulnerability().getRelatedVulnerabilities() != null) {
            List<Integer> cwes = finding.getVulnerability().getRelatedVulnerabilities().stream()
                    .filter(cwe -> cwe.startsWith("CWE-"))
                    .map(cwe -> Integer.parseInt(cwe.substring(4)))
                    .collect(Collectors.toList());
            vuln.setCwes(cwes);
        }

        vuln.setDetail(buildDetailedDescription(finding));
        return vuln;
    }

    private Date parseCodeGuruDate(String dateString) {
        if (dateString == null || dateString.trim().isEmpty()) {
            return new Date();
        }

        try {
            String cleanedDate = dateString.replaceAll("(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})\\.(\\d{3})\\d*", "$1.$2");
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSSXXX");
            return sdf.parse(cleanedDate);
        } catch (ParseException e) {
            LOGGER.warn("Failed to parse date: %s".formatted(dateString));
            return new Date();
        }
    }

    private String computeVulnHash(AWSCodeGuruFinding finding) {
        if (finding.getVulnerability() == null || finding.getVulnerability().getFilePath() == null) {
            throw new IllegalArgumentException("Finding does not contain vulnerability file path information");
        }

        String path = finding.getVulnerability().getFilePath().getPath();
        Integer startLine = finding.getVulnerability().getFilePath().getStartLine();
        List<AWSCodeGuruFinding.Vulnerability.FilePath.CodeSnippet> snippets = finding.getVulnerability().getFilePath().getCodeSnippet();

        if (path == null || snippets == null) {
            throw new IllegalArgumentException("Finding does not contain valid file path or code snippets");
        }

        for (AWSCodeGuruFinding.Vulnerability.FilePath.CodeSnippet snippet : snippets) {
            if (startLine.equals(snippet.getNumber()) && snippet.getContent() != null) {
                String content = snippet.getContent();
                String combined = path + content;
                return DigestUtils.md5Hex(combined);
            }
        }

        throw new IllegalArgumentException("No matching code snippet found for start line: " + startLine);
    }

    /**
     * Build detailed description including file path, line numbers, and code snippet
     */
    private String buildDetailedDescription(AWSCodeGuruFinding finding) {
        StringBuilder detail = new StringBuilder();

        if (finding.getVulnerability() != null && finding.getVulnerability().getFilePath() != null) {
            AWSCodeGuruFinding.Vulnerability.FilePath filePath = finding.getVulnerability().getFilePath();

            detail.append("File: ").append(filePath.getPath()).append("\n");
            detail.append("Lines: ").append(filePath.getStartLine()).append("-").append(filePath.getEndLine()).append("\n");

            if (filePath.getCodeSnippet() != null && !filePath.getCodeSnippet().isEmpty()) {
                detail.append("\nCode Context:\n");
                filePath.getCodeSnippet().forEach(snippet ->
                        detail.append("Line ").append(snippet.getNumber()).append(": ")
                                .append(snippet.getContent()).append("\n")
                );
            }
        }

        return detail.toString();
    }

    private Severity convertSeverity(final String codeGuruSeverity) {
        if (codeGuruSeverity == null) {
            return Severity.UNASSIGNED;
        }

        return switch (codeGuruSeverity.toUpperCase()) {
            case "CRITICAL" -> Severity.CRITICAL;
            case "HIGH" -> Severity.HIGH;
            case "MEDIUM" -> Severity.MEDIUM;
            case "LOW" -> Severity.LOW;
            case "INFO", "INFORMATIONAL" -> Severity.INFO;
            default -> Severity.UNASSIGNED;
        };
    }

    private static List<Component> getAllComponents(final QueryManager qm, final Project project) {
        final Query<Component> query = qm.getPersistenceManager().newQuery(Component.class);
        query.getFetchPlan().addGroup(Component.FetchGroup.ALL.name());
        query.getFetchPlan().setFetchSize(FETCH_SIZE_GREEDY);
        query.setFilter("project.id == :projectId");
        query.setParameters(project.getId());
        try {
            return List.copyOf(query.executeList());
        } finally {
            query.closeAll();
        }
    }

    private long deleteComponentsById(final QueryManager qm, final Collection<Long> componentIds) {
        if (componentIds.isEmpty()) {
            return 0;
        }

        final PersistenceManager pm = qm.getPersistenceManager();
        LOGGER.info("Deleting %d CodeGuru component(s) that are no longer part of the report".formatted(componentIds.size()));

        // Delete related entities first
        pm.newQuery(AnalysisComment.class, ":ids.contains(analysis.component.id)").deletePersistentAll(componentIds);
        pm.newQuery(Analysis.class, ":ids.contains(component.id)").deletePersistentAll(componentIds);
        pm.newQuery(ViolationAnalysisComment.class, ":ids.contains(violationAnalysis.component.id)").deletePersistentAll(componentIds);
        pm.newQuery(ViolationAnalysis.class, ":ids.contains(component.id)").deletePersistentAll(componentIds);
        pm.newQuery(DependencyMetrics.class, ":ids.contains(component.id)").deletePersistentAll(componentIds);
        pm.newQuery(FindingAttribution.class, ":ids.contains(component.id)").deletePersistentAll(componentIds);
        pm.newQuery(PolicyViolation.class, ":ids.contains(component.id)").deletePersistentAll(componentIds);

        // Delete components
        return pm.newQuery(Component.class, ":ids.contains(id)").deletePersistentAll(componentIds);
    }
}