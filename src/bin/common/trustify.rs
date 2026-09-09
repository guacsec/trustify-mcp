use crate::common::trustify_requests::{
    AdvisoryListRequest, AdvisoryUriRequest, PurlVulnerabilitiesRequest, SbomListPackagesRequest,
    SbomListRequest, SbomUriRequest, UrlEncodeRequest, VulnerabilitiesForMultiplePurlsRequest,
    VulnerabilitiesListRequest, VulnerabilityDetailsRequest,
};
use reqwest::{Client, RequestBuilder, Response, Url};
use rmcp::{
    ErrorData, ServerHandler,
    handler::server::wrapper::Parameters,
    model::{
        CallToolResult, ContentBlock, Implementation, ProtocolVersion, ServerCapabilities,
        ServerInfo,
    },
    tool, tool_handler, tool_router,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::time::Duration;
use std::{collections::HashMap, env};
use tokio::sync::OnceCell;
use trustify_auth::client::OpenIdTokenProvider;
use trustify_module_fundamental::vulnerability::model::VulnerabilityDetails;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_PAGE_SIZE: usize = 1_000;
const MAX_PURL_COUNT: usize = 100;
const MAX_PURL_LENGTH: usize = 4_096;

#[derive(Clone)]
pub struct Trustify {
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
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
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
    async fn trustify_info(&self) -> Result<CallToolResult, ErrorData> {
        let url = self.api_url(&[".well-known", "trustify"])?;
        self.get(url).await
    }

    #[tool(description = "Get a list of sboms from a trustify instance")]
    async fn trustify_sboms_list(
        &self,
        Parameters(params): Parameters<SbomListRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        validate_limit(params.limit)?;
        let mut url = self.api_url(&["api", "v2", "sbom"])?;
        url.query_pairs_mut()
            .append_pair("q", &params.query)
            .append_pair("limit", &params.limit.to_string());
        self.get(url).await
    }

    #[tool(description = "Get the details of a SBOM from a trustify instance by SBOM URI")]
    async fn trustify_sbom_details(
        &self,
        Parameters(params): Parameters<SbomUriRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let url = self.api_url(&["api", "v2", "sbom", &params.sbom_uri])?;
        self.get(url).await
    }

    #[tool(description = "Get a list of packages contained in an sboms from a trustify instance")]
    async fn trustify_sbom_list_packages(
        &self,
        Parameters(params): Parameters<SbomListPackagesRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        validate_limit(params.limit)?;
        let mut url = self.api_url(&["api", "v2", "sbom", &params.sbom_uri, "packages"])?;
        url.query_pairs_mut()
            .append_pair("q", &params.query)
            .append_pair("limit", &params.limit.to_string());
        self.get(url).await
    }

    #[tool(
        description = "Provide the SBOM ID URN UUID to get a list of all the advisories with vulnerabilities related to an SBOM from a trustify instance"
    )]
    async fn trustify_sbom_list_advisories(
        &self,
        Parameters(param): Parameters<SbomUriRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let mut url = self.api_url(&["api", "v2", "sbom", &param.sbom_uri, "advisory"])?;
        url.query_pairs_mut()
            .append_pair("limit", &MAX_PAGE_SIZE.to_string())
            .append_pair("offset", "0");
        self.get(url).await
    }

    #[tool(
        description = "Provide a package url-encoded PURL to get the list of vulnerabilities affecting if from a trustify instance"
    )]
    async fn trustify_purl_vulnerabilities(
        &self,
        Parameters(param): Parameters<PurlVulnerabilitiesRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let url = self.api_url(&["api", "v2", "purl", &param.package_uri_or_purl])?;
        self.get(url).await
    }

    #[tool(
        description = "Get a list of vulnerabilities from a trustify instance filtering them by severity and publication date and sorted by publish date"
    )]
    async fn trustify_vulnerabilities_list(
        &self,
        Parameters(params): Parameters<VulnerabilitiesListRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        validate_limit(params.limit)?;
        let mut url = self.api_url(&["api", "v2", "vulnerability"])?;
        let query = format!(
            "{}&published>{}&published<{}",
            params.query, params.published_after, params.published_before
        );
        let sort = format!("{}:{}", params.sort_field, params.sort_direction);
        url.query_pairs_mut()
            .append_pair("limit", &params.limit.to_string())
            .append_pair("offset", "0")
            .append_pair("q", &query)
            .append_pair("sort", &sort);
        self.get(url).await
    }

    #[tool(
        description = "Get a list of vulnerabilities from a trustify instance affecting the array of PURLs provided in input"
    )]
    async fn trustify_vulnerabilities_for_multiple_purls(
        &self,
        Parameters(param): Parameters<VulnerabilitiesForMultiplePurlsRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        validate_purls(&param.purls)?;

        let mut purl_data = HashMap::new();
        purl_data.insert("purls", param.purls);

        let response = self
            .post_raw(
                self.api_url(&["api", "v2", "vulnerability", "analyze"])?,
                &purl_data,
            )
            .await?;

        // Parse the response
        let mut vulnerability_details: HashMap<String, Vec<VulnerabilityDetails>> =
            match deserialize_response(response).await {
                Ok(response_json) => response_json,
                Err(error) => {
                    return Err(ErrorData::internal_error(
                        format!("Trustify API returned error: {:?}", error),
                        None,
                    ));
                }
            };

        // Response "slimming" by removing some data
        for vulnerabilities in vulnerability_details.values_mut() {
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
                    advisory.head.scores = vec![];
                })
            })
        }

        Ok(CallToolResult::success(vec![ContentBlock::json(
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
        // Ok(CallToolResult::success(vec![ContentBlock::json(response)?]))
    }

    #[tool(description = "Get the details of a vulnerability from a trustify instance by CVE ID")]
    async fn trustify_vulnerability_details(
        &self,
        Parameters(param): Parameters<VulnerabilityDetailsRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get(self.api_url(&["api", "v2", "vulnerability", &param.cve_id])?)
            .await
    }

    #[tool(
        description = "Get a list of advisories from a trustify instance filtering them by severity and publication date and sorted by publish date"
    )]
    async fn trustify_advisories_list(
        &self,
        Parameters(params): Parameters<AdvisoryListRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        validate_limit(params.limit)?;
        let mut url = self.api_url(&["api", "v2", "advisory"])?;
        url.query_pairs_mut()
            .append_pair("limit", &params.limit.to_string())
            .append_pair("offset", "0")
            .append_pair("q", &params.query)
            .append_pair("sort", &params.sort);
        self.get(url).await
    }

    #[tool(description = "Get the details of a advisory from a trustify instance by advisory URI")]
    async fn trustify_advisory_details(
        &self,
        Parameters(params): Parameters<AdvisoryUriRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let url = self.api_url(&["api", "v2", "advisory", &params.advisory_uri])?;
        self.get(url).await
    }

    #[tool(description = "URL encode a string")]
    fn url_encode(
        &self,
        Parameters(param): Parameters<UrlEncodeRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(CallToolResult::success(vec![ContentBlock::text(
            urlencoding::encode(param.input.as_str()),
        )]))
    }

    fn api_url(&self, path_segments: &[&str]) -> Result<Url, ErrorData> {
        build_api_url(&self.api_base_url, path_segments)
    }

    async fn get(&self, url: Url) -> Result<CallToolResult, ErrorData> {
        self.call(self.http_client.get(url)).await
    }

    #[allow(dead_code)]
    async fn post<T: Serialize + ?Sized>(
        &self,
        url: Url,
        json: &T,
    ) -> Result<CallToolResult, ErrorData> {
        self.call(self.http_client.post(url).json(json)).await
    }

    async fn call(&self, request_builder: RequestBuilder) -> Result<CallToolResult, ErrorData> {
        // Call and get the response
        let response = self.call_raw(request_builder).await?;

        // Parse the response
        let response_json: Value = match deserialize_response(response).await {
            Ok(response_json) => response_json,
            Err(error) => {
                return Err(ErrorData::internal_error(
                    format!("Trustify API JSON error: {:?}", error),
                    None,
                ));
            }
        };

        Ok(CallToolResult::success(vec![ContentBlock::json(
            response_json,
        )?]))
    }

    async fn post_raw<T: Serialize + ?Sized>(
        &self,
        url: Url,
        json: &T,
    ) -> Result<Response, ErrorData> {
        let body = serialize_json_body(json)?;

        self.call_raw(
            self.http_client
                .post(url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body),
        )
        .await
    }

    async fn call_raw(&self, request_builder: RequestBuilder) -> Result<Response, ErrorData> {
        Self::send(request_builder.bearer_auth(self.get_bearer().await)).await
    }

    async fn send(request_builder: RequestBuilder) -> Result<Response, ErrorData> {
        let response = match request_builder.send().await {
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

fn build_api_url(base_url: &str, path_segments: &[&str]) -> Result<Url, ErrorData> {
    let mut url = Url::parse(base_url).map_err(|error| {
        ErrorData::internal_error(format!("Invalid Trustify API URL: {error}"), None)
    })?;
    url.set_query(None);
    url.set_fragment(None);
    {
        let mut path = url.path_segments_mut().map_err(|_| {
            ErrorData::internal_error("Trustify API URL cannot be used as a base URL", None)
        })?;
        path.extend(path_segments.iter().copied());
    }
    Ok(url)
}

fn validate_limit(limit: usize) -> Result<(), ErrorData> {
    if limit > MAX_PAGE_SIZE {
        return Err(ErrorData::invalid_params(
            format!("The maximum page size is {MAX_PAGE_SIZE}"),
            None,
        ));
    }

    Ok(())
}

fn validate_purls(purls: &[String]) -> Result<(), ErrorData> {
    if purls.len() > MAX_PURL_COUNT {
        return Err(ErrorData::invalid_params(
            format!("A maximum of {MAX_PURL_COUNT} PURLs may be requested"),
            None,
        ));
    }
    if let Some(index) = purls
        .iter()
        .enumerate()
        .find_map(|(index, purl)| (purl.len() > MAX_PURL_LENGTH).then_some(index))
    {
        return Err(ErrorData::invalid_params(
            format!("PURL at index {index} exceeds the maximum length of {MAX_PURL_LENGTH} bytes"),
            None,
        ));
    }

    Ok(())
}

fn serialize_json_body<T: Serialize + ?Sized>(json: &T) -> Result<Vec<u8>, ErrorData> {
    let body = serde_json::to_vec(json).map_err(|error| {
        ErrorData::internal_error(
            format!("Failed to serialize Trustify API request: {error}"),
            None,
        )
    })?;
    if body.len() > MAX_REQUEST_BYTES {
        return Err(ErrorData::invalid_params(
            format!("Trustify API request exceeds the {MAX_REQUEST_BYTES}-byte limit"),
            None,
        ));
    }

    Ok(body)
}

async fn deserialize_response<T: DeserializeOwned>(response: Response) -> Result<T, ErrorData> {
    let body = read_response_body(response).await?;
    serde_json::from_slice(&body).map_err(|error| {
        ErrorData::internal_error(format!("Trustify API JSON error: {error}"), None)
    })
}

async fn read_response_body(mut response: Response) -> Result<Vec<u8>, ErrorData> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(ErrorData::internal_error(
            format!("Trustify API response exceeds the {MAX_RESPONSE_BYTES}-byte limit"),
            None,
        ));
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        ErrorData::internal_error(
            format!("Failed to read Trustify API response: {error}"),
            None,
        )
    })? {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(ErrorData::internal_error(
                format!("Trustify API response exceeds the {MAX_RESPONSE_BYTES}-byte limit"),
                None,
            ));
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

#[tool_handler]
impl ServerHandler for Trustify {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .build(),
        )
        .with_protocol_version(ProtocolVersion::V_2025_03_26)
        .with_server_info(Implementation::new(
            format!("{}-{}", env!("CARGO_PKG_NAME"), env!("CARGO_CRATE_NAME")),
            env!("CARGO_PKG_VERSION"),
        ))
        .with_instructions("This server provides tools for interacting with a Trustify remote instance. The tools are able to retrieve info about the Trustify instance itself, the list of the SBOMs ingested, the packages and the vulnerabilities related to each SBOM. Further it can retrieve the vulnerabilities information ingested. More information about Trustify at https://github.com/trustification/trustify")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_PAGE_SIZE, MAX_PURL_COUNT, MAX_PURL_LENGTH, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
        Trustify, build_api_url, read_response_body, serialize_json_body, validate_limit,
        validate_purls,
    };
    use axum::{Router, body::Body, routing::get};
    use std::sync::Arc;
    use tokio::sync::Barrier;

    #[test]
    fn url_values_are_encoded_as_path_segments_and_query_pairs() {
        let purl = "pkg:maven/org.example/foo@1.0?classifier=sources&scope=runtime#metadata";
        let mut url = build_api_url(
            "https://example.test/trustify?old=value#fragment",
            &["api", "v2", "purl", purl],
        )
        .unwrap();
        url.query_pairs_mut()
            .append_pair("q", "title=a&b#c=d?e")
            .append_pair("sort", "published:desc");

        assert!(url.path().contains("pkg:maven%2Forg.example%2Ffoo@1.0"));
        assert!(
            url.path()
                .contains("%3Fclassifier=sources&scope=runtime%23metadata")
        );
        assert_eq!(
            url.query_pairs().find(|(key, _)| key == "q").unwrap().1,
            "title=a&b#c=d?e"
        );
        assert_eq!(
            url.query_pairs().find(|(key, _)| key == "sort").unwrap().1,
            "published:desc"
        );
        assert!(url.fragment().is_none());
    }

    #[test]
    fn request_limits_reject_oversized_inputs() {
        assert!(validate_limit(MAX_PAGE_SIZE + 1).is_err());
        assert!(validate_purls(&vec![String::from("pkg:test/a@1"); MAX_PURL_COUNT + 1]).is_err());
        assert!(validate_purls(&["x".repeat(MAX_PURL_LENGTH + 1)]).is_err());
        assert!(serialize_json_body(&"x".repeat(MAX_REQUEST_BYTES)).is_err());
    }

    #[tokio::test]
    async fn oversized_responses_are_rejected_before_reading_the_body() {
        let app = Router::new().route(
            "/",
            get(|| async { Body::from(vec![b'x'; MAX_RESPONSE_BYTES + 1]) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(axum::serve(listener, app).into_future());
        let response = reqwest::Client::new()
            .get(format!("http://{address}/"))
            .send()
            .await
            .unwrap();

        assert!(read_response_body(response).await.is_err());
        server.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_requests_do_not_block_the_runtime() {
        let barrier = Arc::new(Barrier::new(2));
        let app = Router::new().route(
            "/",
            get({
                let barrier = Arc::clone(&barrier);
                move || {
                    let barrier = Arc::clone(&barrier);
                    async move {
                        barrier.wait().await;
                        "ok"
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(axum::serve(listener, app).into_future());
        let first_client = reqwest::Client::new();
        let second_client = reqwest::Client::new();
        let url = format!("http://{address}/");

        let (first, second) = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            tokio::join!(
                Trustify::send(first_client.get(&url)),
                Trustify::send(second_client.get(&url)),
            )
        })
        .await
        .expect("concurrent requests should complete");

        assert_eq!(first.unwrap().text().await.unwrap(), "ok");
        assert_eq!(second.unwrap().text().await.unwrap(), "ok");
        server.abort();
    }
}
