use anyhow::Error;
use rmcp::{ServiceExt, transport::TokioChildProcess};
use serde_json::Value;
use std::thread::sleep;
use std::time::Duration;
use std::{env, process::Command};
use test_log::test;
use trustify_test_context::subset::ContainsSubset;

const DEFAULT_READINESS_MAX_ATTEMPTS: u32 = 10;
const DEFAULT_READINESS_INTERVAL_MS: u64 = 200;

fn readiness_max_attempts() -> u32 {
    env::var("MCP_SERVER_READY_MAX_ATTEMPTS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(DEFAULT_READINESS_MAX_ATTEMPTS)
}

fn readiness_interval() -> Duration {
    let interval_ms = env::var("MCP_SERVER_READY_INTERVAL_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_READINESS_INTERVAL_MS);

    Duration::from_millis(interval_ms)
}

const EXPECTED_TOOLS_LIST_RESPONSE: &str = r#"{
  "tools": [
    {
      "name": "trustify_advisory_details",
      "description": "Get the details of a advisory from a trustify instance by advisory URI",
      "inputSchema": {
        "type": "object",
        "properties": {
          "advisory_uri": {
            "description": "Advisory URI",
            "type": "string"
          }
        },
        "required": [
          "advisory_uri"
        ],
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "AdvisoryUriRequest"
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
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "VulnerabilitiesForMultiplePurlsRequest"
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
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "UrlEncodeRequest"
      }
    },
    {
      "name": "trustify_sbom_details",
      "description": "Get the details of a SBOM from a trustify instance by SBOM URI",
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
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "SbomUriRequest"
      }
    },
    {
      "name": "trustify_sboms_list",
      "description": "Get a list of sboms from a trustify instance",
      "inputSchema": {
        "type": "object",
        "properties": {
          "query": {
            "description": "Search query for sboms",
            "type": "string"
          },
          "limit": {
            "description": "Maximum number of sboms to return",
            "type": "integer",
            "format": "uint",
            "minimum": 0
          }
        },
        "required": [
          "query",
          "limit"
        ],
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "SbomListRequest"
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
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "VulnerabilityDetailsRequest"
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
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "SbomUriRequest"
      }
    },
    {
      "name": "trustify_sbom_list_packages",
      "description": "Get a list of packages contained in an sboms from a trustify instance",
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
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "SbomUriRequest"
      }
    },
    {
      "name": "trustify_info",
      "description": "Call the info endpoint for a trustify instance",
      "inputSchema": {
        "type": "object",
        "properties": {}
      }
    },
    {
      "name": "trustify_vulnerabilities_list",
      "description": "Get a list of vulnerabilities from a trustify instance filtering them by severity and publication date and sorted by publish date",
      "inputSchema": {
        "type": "object",
        "properties": {
          "query": {
            "description": "Query for vulnerabilities, e.g. base_severity=critical|high",
            "type": "string"
          },
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
          "sort_field": {
            "description": "Field used to sort the vulnerabilities in the output, e.g. 'published'",
            "type": "string"
          },
          "sort_direction": {
            "description": "Sort direction, values allowed are only 'desc' and 'asc', default is 'desc'",
            "type": "string"
          }
        },
        "required": [
          "query",
          "limit",
          "published_after",
          "published_before",
          "sort_field",
          "sort_direction"
        ],
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "VulnerabilitiesListRequest"
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
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "PurlVulnerabilitiesRequest"
      }
    },
    {
      "name": "trustify_advisories_list",
      "description": "Get a list of advisories from a trustify instance filtering them by severity and publication date and sorted by publish date",
      "inputSchema": {
        "type": "object",
        "properties": {
          "query": {
            "description": "Query for advisories defined using the following EBNF grammar (ISO/IEC 14977):\n                (* Query Grammar - EBNF Compliant *)\n                query = ( values | filter ) , { \"&\" , query } ;\n                values = value , { \"|\" , value } ;\n                filter = field , operator , values ;\n                operator = \"=\" | \"!=\" | \"~\" | \"!~\" | \">=\" | \">\" | \"<=\" | \"<\" ;\n                field = \"average_score\" | \"average_severity\" | \"modified\" | \"title\" ;\n                value = { value_char } ;\n                value_char = escaped_char | normal_char ;\n                escaped_char = \"\\\" , special_char ;\n                normal_char = ? any character except '&', '|', '=', '!', '~', '>', '<', '\\' ? ;\n                special_char = \"&\" | \"|\" | \"=\" | \"!\" | \"~\" | \">\" | \"<\" | \"\\\" ;\n                (* Examples:\n                    - Simple filter: title=example\n                    - Multiple values filter: title=foo|bar|baz\n                    - Complex filter: modified>2024-01-01\n                    - Combined query: title=foo&average_severity=high\n                    - Escaped characters: title=foo\\&bar\n                *)",
            "type": "string"
          },
          "limit": {
            "description": "Maximum number of advisories to return, default 1000",
            "type": "integer",
            "format": "uint",
            "minimum": 0
          },
          "sort": {
            "description": "Query for advisories defined using the following EBNF grammar (ISO/IEC 14977):\n                (* Query Grammar - EBNF Compliant *)\n                sort = field [ ':', order ] { ',' sort }\n                order = ( \"asc\" | \"desc\" )\n                field = \"id\" | \"modified\" | \"title\" ;\n                (* Examples:\n                    - Simple sorting: published:desc\n                *)",
            "type": "string"
          }
        },
        "required": [
          "query",
          "limit",
          "sort"
        ],
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "AdvisoryListRequest"
      }
    }
  ]
}"#;

#[test]
fn tools_list_mcp_inspector_stdio() {
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
    log::debug!("Result {:#?}", result);
    log::debug!(
        "Stderr {:#?}",
        str::from_utf8(&output.stderr).unwrap_or_default()
    );
    let expected_result: Value =
        serde_json::from_str(EXPECTED_TOOLS_LIST_RESPONSE).unwrap_or_default();
    assert!(expected_result.contains_subset(result));
}

#[test]
fn tools_list_mcp_inspector_streamable_http() -> Result<(), Error> {
    run_server_test(
        env!("CARGO_BIN_EXE_streamable"),
        "http://localhost:8082/mcp  --transport http",
    )
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
    assert_eq!(tools.len(), 12);

    Ok(())
}

fn run_server_test(server_command: &str, inspector_cli_parameter: &str) -> Result<(), Error> {
    let mut server = Command::new("sh")
        .arg("-c")
        .arg(server_command)
        .env("API_URL", "")
        .env("OPENID_ISSUER_URL", "")
        .env("OPENID_CLIENT_ID", "")
        .env("OPENID_CLIENT_SECRET", "")
        .env("AUTH_DISABLED", "true")
        .spawn()?;

    let mut is_ready = false;
    let mut last_err: Option<reqwest::Error> = None;
    let max_attempts = readiness_max_attempts();
    let interval = readiness_interval();

    for attempt in 1..=max_attempts {
        log::debug!(
            "waiting for server ready (attempt {attempt}/{max_attempts}, interval {:?})",
            interval
        );

        match reqwest::blocking::get(inspector_cli_parameter) {
            Ok(_) => {
                is_ready = true;
                last_err = None;
                break;
            }
            Err(err) => {
                last_err = Some(err);
            }
        }

        sleep(interval);
    }

    assert!(
        is_ready,
        "Inspector endpoint `{}` never responded after {} attempts (interval {:?}). Last error: {:?}",
        inspector_cli_parameter, max_attempts, interval, last_err
    );

    let inspector_commmand = format!(
        "npx @modelcontextprotocol/inspector --cli {} --method tools/list",
        inspector_cli_parameter
    );
    log::debug!("inspector command: {}", inspector_commmand);
    let output = Command::new("sh")
        .arg("-c")
        .arg(inspector_commmand)
        .output()?;

    server.kill()?;
    log::debug!(
        "Stderr {:#?}",
        str::from_utf8(&output.stderr).unwrap_or_default()
    );

    let result: Value = serde_json::from_str(str::from_utf8(&output.stdout)?)?;
    log::debug!("Result {:#?}", result);

    let expected_result: Value = serde_json::from_str(EXPECTED_TOOLS_LIST_RESPONSE)?;
    assert!(expected_result.contains_subset(result));

    Ok(())
}
