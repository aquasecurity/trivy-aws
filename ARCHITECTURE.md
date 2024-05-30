# Architecture

This document aims to answer the question of *Where is the code that does X?*

## Project Layout

The directory structure is broken down as follows:

- `cmd` - Contains the setup to bootstrap as a Trivy plugin
- `internal/adapters` - Adapters take input - such as a Terraform file or an AWS account - and _adapt_ it to a common format that can be used by the rules engine. This is where the bulk of the code is for supporting new cloud providers.
- `pkg/scanners` - Scanners for various inputs. For example, the `terraform` scanner will scan a Terraform directory and return a list of resources.
- `pkg/state` - The overall state object for Cloud providers is defined here. You should add to the `State` struct if you want to add a new cloud provider.
- `pkg/terraform` - Data structures for describing Terraform resources and modules.
- `pkg/types` - Useful types. Our types wrap a simple data type (e.g. `bool`) and add various metadata to it, such as file name and line number where it was defined.
- `pkg/concurrency` - Data structures used to concurrently adapt resources
- `pkg/cloud` - Helper libraries for AWS cloud scanning
- `test` - Integration tests and other high-level tests that require a full build of the project.
