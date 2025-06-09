use reqwest::blocking::{Client, RequestBuilder, Response};
use rmcp::{Error as McpError, Error, ServerHandler, const_string, model::*, schemars, tool};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use tokio::sync::OnceCell;
use trustify_auth::client::OpenIdTokenProvider;
use trustify_module_fundamental::vulnerability::model::VulnerabilityDetails;

#[derive(Clone)]
pub struct Trustify {
    http_client: Client,
    api_base_url: String,
    openid_issuer_url: String,
    token_provider: OnceCell<OpenIdTokenProvider>,
    open_client_id: String,
    open_client_secret: String,
}

#[tool(tool_box)]
impl Trustify {
    pub fn new() -> Self {
        let api_base_url = env::var("API_URL").expect("Missing the API_URL environment variable.");
        let openid_issuer_url = env::var("OPENID_ISSUER_URL")
            .expect("Missing the OPENID_ISSUER_URL environment variable.");
        let open_client_id = env::var("OPENID_CLIENT_ID")
            .expect("Missing the OPENID_CLIENT_ID environment variable.");
        let open_client_secret = env::var("OPENID_CLIENT_SECRET")
            .expect("Missing the OPENID_CLIENT_SECRET environment variable.");

        // Initialize HTTP client
        let http_client = Client::builder()
            .user_agent("trustify-tools-server")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            http_client,
            api_base_url,
            openid_issuer_url,
            token_provider: OnceCell::default(),
            open_client_id,
            open_client_secret,
        }
    }

    async fn get_token_provider(&self) -> OpenIdTokenProvider {
        let client = openid::Client::discover(
            self.open_client_id.clone(),
            Some(self.open_client_secret.clone()),
            None,
            self.openid_issuer_url.parse().unwrap(),
        )
        .await
        .unwrap();

        OpenIdTokenProvider::new(client, chrono::Duration::seconds(240))
    }

    async fn get_bearer(&self) -> String {
        self.token_provider
            .get_or_init(|| self.get_token_provider())
            .await
            .provide_token()
            .await
            .unwrap()
            .access_token
    }

    #[tool(description = "Call the info endpoint for a trustify instance")]
    async fn trustify_info(&self) -> Result<CallToolResult, McpError> {
        // Trustify /.well-known/trustify URL
        let url = format!("{}/.well-known/trustify", self.api_base_url);
        self.get(url).await
    }

    #[tool(description = "Get a list of sboms from a trustify instance")]
    async fn trustify_sbom_list(
        &self,
        #[tool(param)]
        #[schemars(description = "Search query for sboms")]
        query: String,
        #[tool(param)]
        #[schemars(description = "Maximum number of sboms to return")]
        limit: usize,
    ) -> Result<CallToolResult, McpError> {
        let url = format!(
            "{}/api/v2/sbom?q={}&limit={}",
            self.api_base_url, query, limit
        );
        self.get(url).await
    }

    #[tool(description = "Get a list of packages contained in an sboms from a trustify instance")]
    async fn trustify_sbom_list_packages(
        &self,
        #[tool(param)]
        #[schemars(description = "Sbom URI")]
        sbom_uri: String,
        #[tool(param)]
        #[schemars(description = "Search query for packages within the SBOM")]
        query: String,
        #[tool(param)]
        #[schemars(description = "Maximum number of packages to return")]
        limit: usize,
    ) -> Result<CallToolResult, McpError> {
        let url = format!(
            "{}/api/v2/sbom/{}/packages?q={}&limit={}",
            self.api_base_url, sbom_uri, query, limit
        );
        self.get(url).await
    }

    #[tool(
        description = "Provide the SBOM ID URN UUID to get a list of all the advisories with vulnerabilities related to an SBOM from a trustify instance"
    )]
    async fn trustify_sbom_list_advisories(
        &self,
        #[tool(param)]
        #[schemars(description = "Sbom URI")]
        sbom_uri: String,
    ) -> Result<CallToolResult, McpError> {
        let url = format!("{}/api/v2/sbom/{}/advisory", self.api_base_url, sbom_uri);
        self.get(url).await
    }

    #[tool(
        description = "Provide a package url-encoded PURL to get the list of vulnerabilities affecting if from a trustify instance"
    )]
    async fn trustify_purl_vulnerabilities(
        &self,
        #[tool(param)]
        #[schemars(description = "Package URI or package PURL. Values must be url-encoded")]
        package_uri_or_purl: String,
    ) -> Result<CallToolResult, McpError> {
        let url = format!("{}/api/v2/purl/{}", self.api_base_url, package_uri_or_purl);
        self.get(url).await
    }

    #[tool(
        description = "Get a list of vulnerabilities from a trustify instance filtering them by severity and publication date and sorted by publish date"
    )]
    async fn trustify_vulnerabilities_list(
        &self,
        #[tool(param)]
        #[schemars(description = "Query for vulnerabilities, e.g. base_severity=critical|high")]
        query: String,
        #[tool(param)]
        #[schemars(description = "Maximum number of vulnerabilities to return, default 1000")]
        limit: usize,
        #[tool(param)]
        #[schemars(
            description = "Date after which the vulnerability has to be published, provided in the format 2025-04-20T22:00:00.000Z"
        )]
        published_after: String,
        #[tool(param)]
        #[schemars(
            description = "Date before which the vulnerability has to be published, provided in the format 2025-04-20T22:00:00.000Z"
        )]
        published_before: String,
        #[tool(param)]
        #[schemars(
            description = "Field used to sort the vulnerabilities in the output, e.g. 'published'"
        )]
        sort_field: String,
        #[tool(param)]
        #[schemars(
            description = "Sort direction, values allowed are only 'desc' and 'asc', default is 'desc'"
        )]
        sort_direction: String,
    ) -> Result<CallToolResult, McpError> {
        let url = format!(
            "{}/api/v2/vulnerability?limit={}&offset=0&q={}%26published>{}%26published<{}&sort={}:{}",
            self.api_base_url,
            limit,
            query,
            published_after,
            published_before,
            sort_field,
            sort_direction
        );
        self.get(url).await
    }

    #[tool(
        description = "Get a list of vulnerabilities from a trustify instance affecting the array of PURLs provided in input"
    )]
    async fn trustify_vulnerabilities_for_multiple_purls(
        &self,
        #[tool(param)]
        #[schemars(
            description = r#"Array of PURLs to be investigated for vulnerabilities.
        The array must be delimited by square brackets [] and it must contain strings delimited by double quotes".
        For example: ["pkg:maven/org.jenkins-ci.main/jenkins-core@2.145", "pkg:pypi/tensorflow-gpu@2.6.5"]"#
        )]
        purls: Vec<String>,
    ) -> Result<CallToolResult, McpError> {
        let mut purl_data = HashMap::new();
        purl_data.insert("purls", purls);

        let response = self
            .post_raw(
                format!("{}/api/v2/vulnerability/analyze", self.api_base_url),
                &purl_data,
            )
            .await?;

        // Parse the response
        let mut vulnerability_details: HashMap<String, Vec<VulnerabilityDetails>> =
            match response.json() {
                Ok(response_json) => response_json,
                Err(error) => {
                    return Err(Error::internal_error(
                        format!("Trustify API returned error: {:?}", error),
                        None,
                    ));
                }
            };

        // Response "slimming" by removing some data
        for (_purl, vulnerabilities) in vulnerability_details.iter_mut() {
            vulnerabilities.iter_mut().for_each(|vulnerability| {
                vulnerability.head.description = None;
                vulnerability.head.reserved = None;
                vulnerability.head.modified = None;
                vulnerability.advisories.iter_mut().for_each(|advisory| {
                    advisory.head.head.document_id = "".to_string();
                    advisory.head.head.issuer = None;
                    advisory.head.head.published = None;
                    advisory.head.head.modified = None;
                    advisory.head.head.title = None;
                    advisory.head.severity = None;
                    advisory.head.score = None;
                    advisory.cvss3_scores = vec![];
                })
            })
        }

        Ok(CallToolResult::success(vec![Content::json(
            vulnerability_details,
        )?]))

        // (trivial and basic) example of "DTO" with each PURL associated with just the array of the
        // CVE IDs affecting it
        // let mut response = HashMap::new();
        // for (purl, vulnerabilities) in vulnerability_details.iter() {
        //     // response.insert(purl.as_str(), vulnerabilities[0].head.identifier.clone());
        //     let mut cves: HashSet<String> = HashSet::new();
        //     for vulnerability in vulnerabilities {
        //         cves.insert(vulnerability.head.identifier.clone());
        //     }
        //     response.insert(purl.as_str(), cves);
        // }
        // Ok(CallToolResult::success(vec![Content::json(response)?]))
    }

    #[tool(description = "Get the details of a vulnerability from a trustify instance by CVE ID")]
    async fn trustify_vulnerability_details(
        &self,
        #[tool(param)]
        #[schemars(description = r#"Vulnerability CVE ID"#)]
        cve_id: String,
    ) -> Result<CallToolResult, McpError> {
        self.get(format!(
            "{}/api/v2/vulnerability/{}",
            self.api_base_url, cve_id
        ))
        .await
    }

    #[tool(
        description = "Get a list of advisories from a trustify instance filtering them by severity and publication date and sorted by publish date"
    )]
    async fn trustify_advisories_list(
        &self,
        #[tool(param)]
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
        query: String,
        #[tool(param)]
        #[schemars(description = "Maximum number of advisories to return, default 1000")]
        limit: usize,
        #[tool(param)]
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
        sort: String,
    ) -> Result<CallToolResult, McpError> {
        let url = format!(
            "{}/api/v2/advisory?limit={}&offset=0&q={}&sort={}",
            self.api_base_url, limit, query, sort
        );
        self.get(url).await
    }

    #[tool(description = "URL encode a string")]
    fn url_encode(
        &self,
        #[tool(param)]
        #[schemars(description = "String to be URL encoded")]
        input: String,
    ) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text(
            urlencoding::encode(input.as_str()),
        )]))
    }

    async fn get(&self, url: String) -> Result<CallToolResult, Error> {
        self.call(self.http_client.get(url)).await
    }

    #[allow(dead_code)]
    async fn post<T: Serialize + ?Sized>(
        &self,
        url: String,
        json: &T,
    ) -> Result<CallToolResult, Error> {
        self.call(self.http_client.post(url).json(json)).await
    }

    async fn call(&self, request_builder: RequestBuilder) -> Result<CallToolResult, Error> {
        // Call and get the response
        let response = self.call_raw(request_builder).await?;

        // Parse the response
        let response_json: Value = match response.json() {
            Ok(response_json) => response_json,
            Err(error) => {
                return Err(Error::internal_error(
                    format!("Trustify API returned error: {:?}", error),
                    None,
                ));
            }
        };

        Ok(CallToolResult::success(vec![Content::json(response_json)?]))
    }

    async fn post_raw<T: Serialize + ?Sized>(
        &self,
        url: String,
        json: &T,
    ) -> Result<Response, Error> {
        self.call_raw(self.http_client.post(url).json(json)).await
    }

    async fn call_raw(&self, request_builder: RequestBuilder) -> Result<Response, Error> {
        // Send the request
        let response = match request_builder.bearer_auth(self.get_bearer().await).send() {
            Ok(response) => response,
            Err(error) => {
                return Err(Error::internal_error(
                    format!("Trustify API returned error: {:?}", error),
                    None,
                ));
            }
        };

        // Check if the request was successful
        if !response.status().is_success() {
            return Err(Error::internal_error(
                format!("Trustify API returned status code: {}", response.status()),
                None,
            ));
        }

        Ok(response)
    }
}

const_string!(Echo = "echo");
#[tool(tool_box)]
impl ServerHandler for Trustify {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .build(),
            server_info: Implementation::from_build_env(),
            instructions: Some("This server provides tools for interacting with a Trustify remote instance. The tools are able to retrieve info about the Trustify instance itself, the list of the SBOMs ingested, the packages and the vulnerabilities related to each SBOM. Further it can retrieve the vulnerabilities information ingested. More information about Trustify at https://github.com/trustification/trustify".to_string()),
        }
    }
}
