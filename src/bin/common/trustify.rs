use crate::common::trustify_requests::{
    AdvisoryListRequest, PurlVulnerabilitiesRequest, SbomListPackagesRequest, SbomListRequest,
    SbomUriRequest, UrlEncodeRequest, VulnerabilitiesForMultiplePurlsRequest,
    VulnerabilitiesListRequest, VulnerabilityDetailsRequest,
};
use reqwest::blocking::{Client, RequestBuilder, Response};
use rmcp::{
    ErrorData, ServerHandler,
    handler::server::tool::{Parameters, ToolRouter},
    model::{
        CallToolResult, Content, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
    },
    tool, tool_handler, tool_router,
};
use serde::Serialize;
use serde_json::Value;
use std::{collections::HashMap, env};
use tokio::sync::OnceCell;
use trustify_auth::client::OpenIdTokenProvider;
use trustify_module_fundamental::vulnerability::model::VulnerabilityDetails;

#[derive(Clone)]
pub struct Trustify {
    tool_router: ToolRouter<Self>,
    http_client: Client,
    api_base_url: String,
    openid_issuer_url: String,
    token_provider: OnceCell<OpenIdTokenProvider>,
    open_client_id: String,
    open_client_secret: String,
}

#[tool_router]
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
            tool_router: Self::tool_router(),
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
    async fn trustify_info(&self) -> Result<CallToolResult, ErrorData> {
        // Trustify /.well-known/trustify URL
        let url = format!("{}/.well-known/trustify", self.api_base_url);
        self.get(url).await
    }

    #[tool(description = "Get a list of sboms from a trustify instance")]
    async fn trustify_sbom_list(
        &self,
        Parameters(params): Parameters<SbomListRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let url = format!(
            "{}/api/v2/sbom?q={}&limit={}",
            self.api_base_url, params.query, params.limit
        );
        self.get(url).await
    }

    #[tool(description = "Get a list of packages contained in an sboms from a trustify instance")]
    async fn trustify_sbom_list_packages(
        &self,
        Parameters(sbom_uri_param): Parameters<SbomUriRequest>,
        Parameters(sbom_list_packages_params): Parameters<SbomListPackagesRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let url = format!(
            "{}/api/v2/sbom/{}/packages?q={}&limit={}",
            self.api_base_url,
            sbom_uri_param.sbom_uri,
            sbom_list_packages_params.query,
            sbom_list_packages_params.limit
        );
        self.get(url).await
    }

    #[tool(
        description = "Provide the SBOM ID URN UUID to get a list of all the advisories with vulnerabilities related to an SBOM from a trustify instance"
    )]
    async fn trustify_sbom_list_advisories(
        &self,
        Parameters(param): Parameters<SbomUriRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let url = format!(
            "{}/api/v2/sbom/{}/advisory",
            self.api_base_url, param.sbom_uri
        );
        self.get(url).await
    }

    #[tool(
        description = "Provide a package url-encoded PURL to get the list of vulnerabilities affecting if from a trustify instance"
    )]
    async fn trustify_purl_vulnerabilities(
        &self,
        Parameters(param): Parameters<PurlVulnerabilitiesRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let url = format!(
            "{}/api/v2/purl/{}",
            self.api_base_url, param.package_uri_or_purl
        );
        self.get(url).await
    }

    #[tool(
        description = "Get a list of vulnerabilities from a trustify instance filtering them by severity and publication date and sorted by publish date"
    )]
    async fn trustify_vulnerabilities_list(
        &self,
        Parameters(params): Parameters<VulnerabilitiesListRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let url = format!(
            "{}/api/v2/vulnerability?limit={}&offset=0&q={}%26published>{}%26published<{}&sort={}:{}",
            self.api_base_url,
            params.limit,
            params.query,
            params.published_after,
            params.published_before,
            params.sort_field,
            params.sort_direction
        );
        self.get(url).await
    }

    #[tool(
        description = "Get a list of vulnerabilities from a trustify instance affecting the array of PURLs provided in input"
    )]
    async fn trustify_vulnerabilities_for_multiple_purls(
        &self,
        Parameters(param): Parameters<VulnerabilitiesForMultiplePurlsRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let mut purl_data = HashMap::new();
        purl_data.insert("purls", param.purls);

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
                    return Err(ErrorData::internal_error(
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
        Parameters(param): Parameters<VulnerabilityDetailsRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get(format!(
            "{}/api/v2/vulnerability/{}",
            self.api_base_url, param.cve_id
        ))
        .await
    }

    #[tool(
        description = "Get a list of advisories from a trustify instance filtering them by severity and publication date and sorted by publish date"
    )]
    async fn trustify_advisories_list(
        &self,
        Parameters(params): Parameters<AdvisoryListRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let url = format!(
            "{}/api/v2/advisory?limit={}&offset=0&q={}&sort={}",
            self.api_base_url, params.limit, params.query, params.sort
        );
        self.get(url).await
    }

    #[tool(description = "URL encode a string")]
    fn url_encode(
        &self,
        Parameters(param): Parameters<UrlEncodeRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(CallToolResult::success(vec![Content::text(
            urlencoding::encode(param.input.as_str()),
        )]))
    }

    async fn get(&self, url: String) -> Result<CallToolResult, ErrorData> {
        self.call(self.http_client.get(url)).await
    }

    #[allow(dead_code)]
    async fn post<T: Serialize + ?Sized>(
        &self,
        url: String,
        json: &T,
    ) -> Result<CallToolResult, ErrorData> {
        self.call(self.http_client.post(url).json(json)).await
    }

    async fn call(&self, request_builder: RequestBuilder) -> Result<CallToolResult, ErrorData> {
        // Call and get the response
        let response = self.call_raw(request_builder).await?;

        // Parse the response
        let response_json: Value = match response.json() {
            Ok(response_json) => response_json,
            Err(error) => {
                return Err(ErrorData::internal_error(
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
    ) -> Result<Response, ErrorData> {
        self.call_raw(self.http_client.post(url).json(json)).await
    }

    async fn call_raw(&self, request_builder: RequestBuilder) -> Result<Response, ErrorData> {
        // Send the request
        let response = match request_builder.bearer_auth(self.get_bearer().await).send() {
            Ok(response) => response,
            Err(error) => {
                return Err(ErrorData::internal_error(
                    format!("Trustify API returned error: {error:?}"),
                    None,
                ));
            }
        };

        // Check if the request was successful
        if !response.status().is_success() {
            return Err(ErrorData::internal_error(
                format!("Trustify API returned status code: {}", response.status()),
                None,
            ));
        }

        Ok(response)
    }
}

#[tool_handler]
impl ServerHandler for Trustify {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2025_03_26,
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .build(),
            server_info: Implementation {
                name: format!("{}-{}", env!("CARGO_PKG_NAME"), env!("CARGO_CRATE_NAME")).to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            instructions: Some("This server provides tools for interacting with a Trustify remote instance. The tools are able to retrieve info about the Trustify instance itself, the list of the SBOMs ingested, the packages and the vulnerabilities related to each SBOM. Further it can retrieve the vulnerabilities information ingested. More information about Trustify at https://github.com/trustification/trustify".to_string()),
        }
    }
}
