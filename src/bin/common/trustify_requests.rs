use rmcp::schemars;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SbomListRequest {
    #[schemars(description = "Search query for sboms")]
    pub query: String,
    #[schemars(description = "Maximum number of sboms to return")]
    pub limit: usize,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SbomUriRequest {
    #[schemars(description = "Sbom URI")]
    pub(crate) sbom_uri: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SbomListPackagesRequest {
    // #[schemars(description = "Sbom URI")]
    // sbom_uri: String,
    #[schemars(description = "Search query for packages within the SBOM")]
    pub(crate) query: String,
    #[schemars(description = "Maximum number of packages to return")]
    pub(crate) limit: usize,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct VulnerabilitiesListRequest {
    #[schemars(description = "Query for vulnerabilities, e.g. base_severity=critical|high")]
    pub(crate) query: String,
    #[schemars(description = "Maximum number of vulnerabilities to return, default 1000")]
    pub(crate) limit: usize,
    #[schemars(
        description = "Date after which the vulnerability has to be published, provided in the format 2025-04-20T22:00:00.000Z"
    )]
    pub(crate) published_after: String,
    #[schemars(
        description = "Date before which the vulnerability has to be published, provided in the format 2025-04-20T22:00:00.000Z"
    )]
    pub(crate) published_before: String,
    #[schemars(
        description = "Field used to sort the vulnerabilities in the output, e.g. 'published'"
    )]
    pub(crate) sort_field: String,
    #[schemars(
        description = "Sort direction, values allowed are only 'desc' and 'asc', default is 'desc'"
    )]
    pub(crate) sort_direction: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct PurlVulnerabilitiesRequest {
    #[schemars(description = "Package URI or package PURL. Values must be url-encoded")]
    pub(crate) package_uri_or_purl: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct VulnerabilitiesForMultiplePurlsRequest {
    #[schemars(
        description = r#"Array of PURLs to be investigated for vulnerabilities.
        The array must be delimited by square brackets [] and it must contain strings delimited by double quotes".
        For example: ["pkg:maven/org.jenkins-ci.main/jenkins-core@2.145", "pkg:pypi/tensorflow-gpu@2.6.5"]"#
    )]
    pub(crate) purls: Vec<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct VulnerabilityDetailsRequest {
    #[schemars(description = r#"Vulnerability CVE ID"#)]
    pub(crate) cve_id: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AdvisoryListRequest {
    #[schemars(
        description = r#"Query for advisories defined using the following EBNF grammar (ISO/IEC 14977):
                (* Query Grammar - EBNF Compliant *)
                query = ( values | filter ) , { "&" , query } ;
                values = value , { "|" , value } ;
                filter = field , operator , values ;
                operator = "=" | "!=" | "~" | "!~" | ">=" | ">" | "<=" | "<" ;
                field = "average_score" | "average_severity" | "modified" | "title" ;
                value = { value_char } ;
                value_char = escaped_char | normal_char ;
                escaped_char = "\" , special_char ;
                normal_char = ? any character except '&', '|', '=', '!', '~', '>', '<', '\' ? ;
                special_char = "&" | "|" | "=" | "!" | "~" | ">" | "<" | "\" ;
                (* Examples:
                    - Simple filter: title=example
                    - Multiple values filter: title=foo|bar|baz
                    - Complex filter: modified>2024-01-01
                    - Combined query: title=foo&average_severity=high
                    - Escaped characters: title=foo\&bar
                *)"#
    )]
    pub(crate) query: String,
    #[schemars(description = "Maximum number of advisories to return, default 1000")]
    pub(crate) limit: usize,
    #[schemars(
        description = r#"Query for advisories defined using the following EBNF grammar (ISO/IEC 14977):
                (* Query Grammar - EBNF Compliant *)
                sort = field [ ':', order ] { ',' sort }
                order = ( "asc" | "desc" )
                field = "id" | "modified" | "title" ;
                (* Examples:
                    - Simple sorting: published:desc
                *)"#
    )]
    pub(crate) sort: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AdvisoryUriRequest {
    #[schemars(description = "Advisory URI")]
    pub(crate) advisory_uri: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct UrlEncodeRequest {
    #[schemars(description = "String to be URL encoded")]
    pub(crate) input: String,
}
