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

package org.dependencytrack.parser.awscodeguru;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class AWSCodeGuruFinding {
    private String createdAt;
    private String description;
    private String detectorId;
    private String detectorName;
    private List<String> detectorTags;
    private String generatorId;
    private String id;
    private Remediation remediation;
    private Resource resource;
    private String ruleId;
    private String severity;
    private String status;
    private String title;
    private String type;
    private String updatedAt;
    private Vulnerability vulnerability;

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Remediation {
        private Recommendation recommendation;
        private List<SuggestedFix> suggestedFixes;

        public static class Recommendation {
            private String text;
            private String url;

            public String getText() {
                return text;
            }

            public void setText(String text) {
                this.text = text;
            }

            @JsonProperty("url")
            public String getUrl() {
                return url;
            }

            public void setUrl(String url) {
                this.url = url;
            }
        }

        public static class SuggestedFix {
            private String code;
            private String description;

            public String getCode() {
                return code;
            }

            public void setCode(String code) {
                this.code = code;
            }

            public String getDescription() {
                return description;
            }

            public void setDescription(String description) {
                this.description = description;
            }
        }

        public Recommendation getRecommendation() {
            return recommendation;
        }

        public void setRecommendation(Recommendation recommendation) {
            this.recommendation = recommendation;
        }

        public List<SuggestedFix> getSuggestedFixes() {
            return suggestedFixes;
        }

        public void setSuggestedFixes(List<SuggestedFix> suggestedFixes) {
            this.suggestedFixes = suggestedFixes;
        }
    }

    public static class Resource {
        private String id;

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }
    }

    public static class Vulnerability {
        private FilePath filePath;
        private String id;
        private List<String> referenceUrls;
        private List<String> relatedVulnerabilities;

        public static class FilePath {
            private List<CodeSnippet> codeSnippet;
            private int endLine;
            private String name;
            private String path;
            private int startLine;

            public static class CodeSnippet {
                private String content;
                private int number;

                public String getContent() {
                    return content;
                }

                public void setContent(String content) {
                    this.content = content;
                }

                public int getNumber() {
                    return number;
                }

                public void setNumber(int number) {
                    this.number = number;
                }
            }

            public List<CodeSnippet> getCodeSnippet() {
                return codeSnippet;
            }

            public void setCodeSnippet(List<CodeSnippet> codeSnippet) {
                this.codeSnippet = codeSnippet;
            }

            public int getEndLine() {
                return endLine;
            }

            public void setEndLine(int endLine) {
                this.endLine = endLine;
            }

            public String getName() {
                return name;
            }

            public void setName(String name) {
                this.name = name;
            }

            public String getPath() {
                return path;
            }

            public void setPath(String path) {
                this.path = path;
            }

            public int getStartLine() {
                return startLine;
            }

            public void setStartLine(int startLine) {
                this.startLine = startLine;
            }
        }

        public FilePath getFilePath() {
            return filePath;
        }

        public void setFilePath(FilePath filePath) {
            this.filePath = filePath;
        }

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public List<String> getReferenceUrls() {
            return referenceUrls;
        }

        public void setReferenceUrls(List<String> referenceUrls) {
            this.referenceUrls = referenceUrls;
        }

        public List<String> getRelatedVulnerabilities() {
            return relatedVulnerabilities;
        }

        public void setRelatedVulnerabilities(List<String> relatedVulnerabilities) {
            this.relatedVulnerabilities = relatedVulnerabilities;
        }
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getDetectorId() {
        return detectorId;
    }

    public void setDetectorId(String detectorId) {
        this.detectorId = detectorId;
    }

    public String getDetectorName() {
        return detectorName;
    }

    public void setDetectorName(String detectorName) {
        this.detectorName = detectorName;
    }

    public List<String> getDetectorTags() {
        return detectorTags;
    }

    public void setDetectorTags(List<String> detectorTags) {
        this.detectorTags = detectorTags;
    }

    public String getGeneratorId() {
        return generatorId;
    }

    public void setGeneratorId(String generatorId) {
        this.generatorId = generatorId;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Remediation getRemediation() {
        return remediation;
    }

    public void setRemediation(Remediation remediation) {
        this.remediation = remediation;
    }

    public Resource getResource() {
        return resource;
    }

    public void setResource(Resource resource) {
        this.resource = resource;
    }

    public String getRuleId() {
        return ruleId;
    }

    public void setRuleId(String ruleId) {
        this.ruleId = ruleId;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(String updatedAt) {
        this.updatedAt = updatedAt;
    }

    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    public void setVulnerability(Vulnerability vulnerability) {
        this.vulnerability = vulnerability;
    }
}
