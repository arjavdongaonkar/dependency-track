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

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class CodeGuruResponse {
    @JsonProperty("ResponseMetadata")
    private ResponseMetadata responseMetadata;

    @JsonProperty("findings")
    private List<AWSCodeGuruFinding> findings;

    // Getters and setters
    public ResponseMetadata getResponseMetadata() {
        return responseMetadata;
    }

    public void setResponseMetadata(ResponseMetadata responseMetadata) {
        this.responseMetadata = responseMetadata;
    }

    public List<AWSCodeGuruFinding> getFindings() {
        return findings;
    }

    public void setFindings(List<AWSCodeGuruFinding> findings) {
        this.findings = findings;
    }
}
