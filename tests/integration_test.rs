use anyhow::Error;
use rmcp::{ServiceExt, transport::TokioChildProcess};
use serde_json::json;
use std::{env, process::Command};
use trustify_test_context::subset::ContainsSubset;

#[test]
fn tools_list_mcp_inspector() {
    let inspector_commmand = format!(
        "npx @modelcontextprotocol/inspector --cli {} --method tools/list",
        env!("CARGO_BIN_EXE_stdio")
    );
    log::debug!("inspector command: {}", inspector_commmand);
    let output = Command::new("sh")
        .arg("-c")
        .arg(inspector_commmand)
        .env("API_URL", "")
        .env("OPENID_ISSUER_URL", "")
        .env("OPENID_CLIENT_ID", "")
        .env("OPENID_CLIENT_SECRET", "")
        .output()
        .expect("failed to execute process");

    let result = serde_json::from_str(str::from_utf8(&output.stdout).unwrap_or_default())
        .unwrap_or_default();
    log::debug!("{:#?}", result);
    log::debug!("{:#?}", str::from_utf8(&output.stderr).unwrap_or_default());
    let expected_result = json!({
      "tools": [
        {
          "name": "trustify_vulnerabilities_list",
          "description": "Get a list of vulnerabilities from a trustify instance filtering them by severity and publication date and sorted by publish date",
          "inputSchema": {
            "type": "object",
            "properties": {
              "limit": {
                "description": "Maximum number of vulnerabilities to return, default 1000",
                "type": "integer",
                "format": "uint",
                "minimum": 0
              },
              "published_after": {
                "description": "Date after which the vulnerability has to be published, provided in the format 2025-04-20T22:00:00.000Z",
                "type": "string"
              },
              "published_before": {
                "description": "Date before which the vulnerability has to be published, provided in the format 2025-04-20T22:00:00.000Z",
                "type": "string"
              },
              "query": {
                "description": "Query for vulnerabilities, e.g. base_severity=critical|high",
                "type": "string"
              },
              "sort_direction": {
                "description": "Sort direction, values allowed are only 'desc' and 'asc', default is 'desc'",
                "type": "string"
              },
              "sort_field": {
                "description": "Field used to sort the vulnerabilities in the output, e.g. 'published'",
                "type": "string"
              }
            },
            "required": [
              "limit",
              "published_after",
              "published_before",
              "query",
              "sort_direction",
              "sort_field"
            ],
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "VulnerabilitiesListRequest"
          }
        },
        {
          "name": "trustify_vulnerability_details",
          "description": "Get the details of a vulnerability from a trustify instance by CVE ID",
          "inputSchema": {
            "type": "object",
            "properties": {
              "cve_id": {
                "description": "Vulnerability CVE ID",
                "type": "string"
              }
            },
            "required": [
              "cve_id"
            ],
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "VulnerabilityDetailsRequest"
          }
        },
        {
          "name": "trustify_info",
          "description": "Call the info endpoint for a trustify instance",
          "inputSchema": {
            "type": "object",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "EmptyObject",
            "description": "This is commonly used for representing empty objects in MCP messages.\n\nwithout returning any specific data."
          }
        },
        {
          "name": "trustify_advisories_list",
          "description": "Get a list of advisories from a trustify instance filtering them by severity and publication date and sorted by publish date",
          "inputSchema": {
            "type": "object",
            "properties": {
              "limit": {
                "description": "Maximum number of advisories to return, default 1000",
                "type": "integer",
                "format": "uint",
                "minimum": 0
              },
              "query": {
                "description": "Query for advisories defined using the following EBNF grammar (ISO/IEC 14977):\n                (* Query Grammar - EBNF Compliant *)\n                query = ( values | filter ) , { \"&\" , query } ;\n                values = value , { \"|\" , value } ;\n                filter = field , operator , values ;\n                operator = \"=\" | \"!=\" | \"~\" | \"!~\" | \">=\" | \">\" | \"<=\" | \"<\" ;\n                field = \"average_score\" | \"average_severity\" | \"modified\" | \"title\" ;\n                value = { value_char } ;\n                value_char = escaped_char | normal_char ;\n                escaped_char = \"\\\" , special_char ;\n                normal_char = ? any character except '&', '|', '=', '!', '~', '>', '<', '\\' ? ;\n                special_char = \"&\" | \"|\" | \"=\" | \"!\" | \"~\" | \">\" | \"<\" | \"\\\" ;\n                (* Examples:\n                    - Simple filter: title=example\n                    - Multiple values filter: title=foo|bar|baz\n                    - Complex filter: modified>2024-01-01\n                    - Combined query: title=foo&average_severity=high\n                    - Escaped characters: title=foo\\&bar\n                *)",
                "type": "string"
              },
              "sort": {
                "description": "Query for advisories defined using the following EBNF grammar (ISO/IEC 14977):\n                (* Query Grammar - EBNF Compliant *)\n                sort = field [ ':', order ] { ',' sort }\n                order = ( \"asc\" | \"desc\" )\n                field = \"id\" | \"modified\" | \"title\" ;\n                (* Examples:\n                    - Simple sorting: published:desc\n                *)",
                "type": "string"
              }
            },
            "required": [
              "limit",
              "query",
              "sort"
            ],
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "AdvisoryListRequest"
          }
        },
        {
          "name": "trustify_purl_vulnerabilities",
          "description": "Provide a package url-encoded PURL to get the list of vulnerabilities affecting if from a trustify instance",
          "inputSchema": {
            "type": "object",
            "properties": {
              "package_uri_or_purl": {
                "description": "Package URI or package PURL. Values must be url-encoded",
                "type": "string"
              }
            },
            "required": [
              "package_uri_or_purl"
            ],
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "PurlVulnerabilitiesRequest"
          }
        },
        {
          "name": "trustify_sbom_list_advisories",
          "description": "Provide the SBOM ID URN UUID to get a list of all the advisories with vulnerabilities related to an SBOM from a trustify instance",
          "inputSchema": {
            "type": "object",
            "properties": {
              "sbom_uri": {
                "description": "Sbom URI",
                "type": "string"
              }
            },
            "required": [
              "sbom_uri"
            ],
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "SbomUriRequest"
          }
        },
        {
          "name": "trustify_sbom_list",
          "description": "Get a list of sboms from a trustify instance",
          "inputSchema": {
            "type": "object",
            "properties": {
              "limit": {
                "description": "Maximum number of sboms to return",
                "type": "integer",
                "format": "uint",
                "minimum": 0
              },
              "query": {
                "description": "Search query for sboms",
                "type": "string"
              }
            },
            "required": [
              "limit",
              "query"
            ],
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "SbomListRequest"
          }
        },
        {
          "name": "url_encode",
          "description": "URL encode a string",
          "inputSchema": {
            "type": "object",
            "properties": {
              "input": {
                "description": "String to be URL encoded",
                "type": "string"
              }
            },
            "required": [
              "input"
            ],
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "UrlEncodeRequest"
          }
        },
        {
          "name": "trustify_vulnerabilities_for_multiple_purls",
          "description": "Get a list of vulnerabilities from a trustify instance affecting the array of PURLs provided in input",
          "inputSchema": {
            "type": "object",
            "properties": {
              "purls": {
                "description": "Array of PURLs to be investigated for vulnerabilities.\n        The array must be delimited by square brackets [] and it must contain strings delimited by double quotes\".\n        For example: [\"pkg:maven/org.jenkins-ci.main/jenkins-core@2.145\", \"pkg:pypi/tensorflow-gpu@2.6.5\"]",
                "type": "array",
                "items": {
                  "type": "string"
                }
              }
            },
            "required": [
              "purls"
            ],
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "VulnerabilitiesForMultiplePurlsRequest"
          }
        },
        {
          "name": "trustify_sbom_list_packages",
          "description": "Get a list of packages contained in an sboms from a trustify instance",
          "inputSchema": {
            "type": "object",
            "properties": {
              "limit": {
                "description": "Maximum number of packages to return",
                "type": "integer",
                "format": "uint",
                "minimum": 0
              },
              "query": {
                "description": "Search query for packages within the SBOM",
                "type": "string"
              },
              "sbom_uri": {
                "description": "Sbom URI",
                "type": "string"
              }
            },
            "required": [
              "limit",
              "query",
              "sbom_uri"
            ],
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "SbomUriRequest"
          }
        }
      ]
    });
    assert!(expected_result.contains_subset(result));
}

#[tokio::test]
async fn tools_list_mcp_client() -> Result<(), Error> {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_stdio"));
    command
        .env("API_URL", "")
        .env("OPENID_ISSUER_URL", "")
        .env("OPENID_CLIENT_ID", "")
        .env("OPENID_CLIENT_SECRET", "");
    // Start server
    let service = ().serve(TokioChildProcess::new(command)?).await?;

    // Initialize
    let server_info = service.peer_info();
    log::debug!("Connected to server: {server_info:#?}");
    assert_eq!(server_info.unwrap().server_info.name, "mcp-stdio");

    // List tools
    let tools = service.list_all_tools().await?;
    log::debug!("Available tools: {tools:#?}");
    assert_eq!(tools.len(), 10);

    Ok(())
}
