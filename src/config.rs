// TOML config parsing and validation for neurond.toml.
// See specs/neurond-federation-spec.md for the full schema.
//
// Currently neurond reads policy.toml for the policy engine.
// This module will additionally parse neurond.toml for server bind address,
// TLS settings, audit path, and [[federation.servers]] stanzas.
//
// TODO: implement NeurondConfig, ServerConfig, FederationConfig, DownstreamServer,
//       DownstreamTransport — see tasks/todo.md "FEAT: Config schema — neurond.toml"
