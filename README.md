# mcp

This project provides an implementation of on MCP (Model Context Protocol) server relying upon the [official MCP rust-sdk](https://github.com/modelcontextprotocol/rust-sdk) and heavily inspired but the examples that project provides.
Both the Stdio and SSE transports are supported.

## Env variables

To run the MCP server, both stdio and SSE, some env variables must be provided in order to interact with a Trustify instance:

- API_URL: the base URL of a Trustify instance
- OPENID_ISSUER_URL: The URL of the issuer fpr the OpenID provider
- OPENID_CLIENT_ID: The ID of the client for the OpenID provider
- OPENID_CLIENT_SECRET: The secret of the client for the OpenID provider

## Stdio

The MCP Clients, e.g. [MCP Inspector](https://github.com/modelcontextprotocol/inspector) and Claude Desktop, usually requires the path to the binary of the MCP Server so it's a matter of building the Trustify MCP Server with the stdio transportation in order to consume it from MCP Clients.  
To build it, run the command:

```shell
cargo build --release --bin stdio
```

and the built binary for the Trustify MCP Server will be available at the path `target/release/stdio`.

## SSE

To run the MCP Server with the SSE transportation using `cargo run`, execute

```shell
API_URL=<API URL> OPENID_ISSUER_URL=<OpenID Issuer URL> OPENID_CLIENT_ID=<OpenID Client ID> OPENID_CLIENT_SECRET=<OpenID Client secret> cargo run --release --bin sse
```
and it will be available at the URL http://localhost:8081/sse