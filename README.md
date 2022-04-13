# aws-cli-oidc

CLI tool for retrieving AWS temporary credentials using OIDC provider.

## Rationale behind my local modifications

With All Due Respect, I ...

- Turned off exec bits of some files, I am assuming the original author got a Windows laptop
- Modified way of error reporting, but didn't change every case
- Other opinionated tweaks, and ...

The biggest problem it tried to solve: "No OpenIDConnect provider found in your account for ..."

I was too impatient to read the details, recklessly redid the same functionality with AWS SDK v2.
Later it turns out I could just use `env AWS_SDK_LOAD_CONFIG=1 aws-cli-oidc ...` to make it work...

Anyways, I am not a fan of the env hack so I go with v2. Or maybe I should load the shared config?

## How does it work?

[AWS Identity Providers and Federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers.html) supports IdPs that are compatible with [OpenID Connect (OIDC)](http://openid.net/connect/) or [SAML 2.0 (Security Assertion Markup Language 2.0)](https://wiki.oasis-open.org/security). This tool works with both types of IdP if it supports OIDC because it works as OIDC client. If the federation between the AWS account and the IdP is established, and an OIDC client for this tool is registered in the IdP, you can get AWS temporary credentials via standard browser login. It means you don't need to pass your credential of the IdP to this tool.

Please refer the following diagrams how it works.

### Federation type: OIDC

![flow with oidc](flow-with-oidc.png)

### Federation type: SAML 2.0

**Note: The OIDC provider must support [OAuth 2.0 Token Exchange](https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-15) for exchanging access token/ID token and SAML2 assertion.**

![flow with saml2](flow-with-saml2.png)

## Prerequisite AWS and OIDC provider settings before using this tool

Before using this tool, the system administrator need to setup the following configuration.

- Identity Federation using SAML2/OIDC between AWS and the OIDC provider. See https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers.html
- Registration OIDC/OAuth2 client for this CLI tool in the OIDC provider. Note: The OIDC provider must allow any port to be specified at the time of the request for loopback IP redirect URIs because this tool follows [RFC 8252 OAuth 2.0 for Native Apps 7.3 Loopback Interface Redirection](https://tools.ietf.org/html/rfc8252#section-7.3).

Also depending on the federation type between AWS and the OIDC provider, requirements for the OIDC providers will change.

### Federation type: OIDC

- The OIDC provider only needs to support OIDC. SAML2 and OAuth 2.0 Token Exchange are not necessary. Very simple.
- However, the JWKS endpoint of the OIDC provider needs to export it to the Internet because AWS try to access the endpoint to obtain the public key and to verify the ID token which is issued by the provider.

### Federation type: OIDC-V2 (with AWS SDK v2)

Use configuration: `oidc-v2` when prompted

### Federation type: SAML 2.0

- Of course, the OIDC provider must support not only OIDC but also SAML2 for federation between itself and AWS.
- The OIDC provider must support [OAuth 2.0 Token Exchange](https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-15) for exchanging access token/ID token and SAML2 assertion. `aws-cli-oidc` gets access token/ID token from the OIDC provider first, then it needs to get SAML2 assertion from the provider which is required for getting AWS temporary credentials using AWS STS API.

## Tested OIDC Provider

| OIDC Provider                                                                  | OIDC | SAML2       |
| ------------------------------------------------------------------------------ | ---- | ----------- |
| [Google account](https://accounts.google.com/.well-known/openid-configuration) | OK   | -           |
| [Keycloak](https://www.keycloak.org)                                           | OK   | OK (Note 1) |

- Note 1: You need to use Keycloak 12 or higher that supports exchanging from access token to SAML2 assertion. Also, you need to enable Token Exchange feature.

## Install

Download from [Releases page](https://github.com/openstandia/aws-cli-oidc/releases).

## Usage

```
CLI tool for retrieving AWS temporary credentials using OIDC provider

Usage:
  aws-cli-oidc [command]

Available Commands:
  clear-secret Clear OS secret store that saves AWS credentials
  completion   generate the autocompletion script for the specified shell
  get-cred     Get AWS credentials and out to stdout
  help         Help about any command
  setup        Interactive setup of aws-cli-oidc

Flags:
  -h, --help   help for aws-cli-oidc

Use "aws-cli-oidc [command] --help" for more information about a command.
```

### Setup

Use `aws-cli-oidc setup` command and follow the guide.

### Get AWS temporary credentials

Use `aws-cli-oidc get-cred -p <your oidc provider name>` command. It opens your browser.
Now you can see the login page which the OIDC provider offers. Then do login.
If successful, AWS temporary credentials will be shown as below.

```
aws-cli-oidc get-cred -p myop
Using config file: /home/wadahiro/.aws-cli-oidc/config.yaml
Login successful!
Selected role: arn:aws:iam::123456789012:role/developer
PrincipalARN: arn:aws:iam::123456789012:saml-provider/myop
RoleARN: arn:aws:iam::123456789012:role/developer

export AWS_ACCESS_KEY_ID=ASIAT......
export AWS_SECRET_ACCESS_KEY=9bkS0whPelMYQ.......
export AWS_SESSION_TOKEN=FQoGZXIvYXdzENz.......
```

### Integrate aws-cli

[Sourcing credentials with an external process](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html) describes how to integrate aws-cli with external tool.
You can use `aws-cli-oidc` as the external process. Add the following lines to your `.aws/config` file.

```
[profile foo-developer]
credential_process=aws-cli-oidc get-cred -p myop -r arn:aws:iam::123456789012:role/developer -j -s -d 43200
```

Caution: The AWS temporary credentials will be saved into your OS secret store by using `-s` option to reduce authentication each time you use `aws-cli` tool.

## Licence

Licensed under the [MIT](/LICENSE) license.

## Author

- [Hiroyuki Wada](https://github.com/wadahiro)
