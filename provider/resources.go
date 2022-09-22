// Copyright 2016-2018, Pulumi Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package provider

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	awsbase "github.com/hashicorp/aws-sdk-go-base/v2"
	awsShim "github.com/hashicorp/terraform-provider-aws/shim"
	"github.com/mitchellh/go-homedir"
	//"github.com/pulumi/pulumi-aws/provider/v5/pkg/version"
	"github.com/pulumi/pulumi-terraform-bridge/v3/pkg/tfbridge"
	shim "github.com/pulumi/pulumi-terraform-bridge/v3/pkg/tfshim"
	shimv2 "github.com/pulumi/pulumi-terraform-bridge/v3/pkg/tfshim/sdk-v2"
	"github.com/pulumi/pulumi/pkg/v3/codegen/schema"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/common/tokens"
)

// all of the AWS token components used below.
const (
	// packages:
	awsPkg = "aws"
	// modules:
	awsMod = "index" // the root index.
	iamMod = "Iam"   // Identity and Access Management (IAM)
)

var namespaceMap = map[string]string{
	"aws": "Aws",
}

// awsMember manufactures a type token for the AWS package and the given module, file name, and type.
func awsMember(moduleTitle string, fn string, mem string, experimental bool) tokens.ModuleMember {
	if experimental {
		moduleTitle = fmt.Sprintf("x/%s", moduleTitle)
	}

	moduleName := strings.ToLower(moduleTitle)
	namespaceMap[moduleName] = moduleTitle
	if fn != "" {
		moduleName += "/" + fn
	}
	return tokens.ModuleMember(awsPkg + ":" + moduleName + ":" + mem)
}

// awsType manufactures a type token for the AWS package and the given module, file name, and type.
func awsType(mod string, fn string, typ string) tokens.Type {
	return tokens.Type(awsMember(mod, fn, typ, false))
}

// awsResource manufactures a standard resource token given a module and resource name.  It automatically uses the AWS
// package and names the file by simply lower casing the type's first character.
func awsTypeDefaultFile(mod string, typ string) tokens.Type {
	fn := string(unicode.ToLower(rune(typ[0]))) + typ[1:]
	return awsType(mod, fn, typ)
}

// awsDataSource manufactures a standard resource token given a module and resource name.  It automatically uses the AWS
// package and names the file by simply lower casing the data source's first character.
func awsDataSource(mod string, res string) tokens.ModuleMember {
	fn := string(unicode.ToLower(rune(res[0]))) + res[1:]
	return awsMember(mod, fn, res, false)
}

func awsExperimentalDataSource(mod string, res string) tokens.ModuleMember {
	fn := string(unicode.ToLower(rune(res[0]))) + res[1:]
	return awsMember(mod, fn, res, true)
}

// awsResource manufactures a standard resource token given a module and resource name.
func awsResource(mod string, res string) tokens.Type {
	return awsTypeDefaultFile(mod, res)
}

// boolRef returns a reference to the bool argument.
// func boolRef(b bool) *bool {
// 	return &b
// }

// stringValue gets a string value from a property map if present, else ""
func stringValue(vars resource.PropertyMap, prop resource.PropertyKey, envs []string) string {
	val, ok := vars[prop]
	if ok && val.IsString() {
		return val.StringValue()
	}
	for _, env := range envs {
		val, ok := os.LookupEnv(env)
		if ok {
			return val
		}
	}
	return ""
}

func arrayValue(vars resource.PropertyMap, prop resource.PropertyKey, envs []string) []string {
	val, ok := vars[prop]
	var vals []string
	if ok && val.IsArray() {
		for _, v := range val.ArrayValue() {
			vals = append(vals, v.StringValue())
		}
		return vals
	}

	for _, env := range envs {
		val, ok := os.LookupEnv(env)
		if ok {
			return strings.Split(val, ";")
		}
	}
	return vals
}

// func stringRef(s string) *string {
// 	return &s
// }

// preConfigureCallback validates that AWS credentials can be successfully discovered. This emulates the credentials
// configuration subset of `github.com/terraform-providers/terraform-provider-aws/aws.providerConfigure`.  We do this
// before passing control to the TF provider to ensure we can report actionable errors.
func preConfigureCallback(vars resource.PropertyMap, c shim.ResourceConfig) error {
	var skipCredentialsValidation bool
	if val, ok := vars["skipCredentialsValidation"]; ok {
		if val.IsBool() {
			skipCredentialsValidation = val.BoolValue()
		}
	}

	// if we skipCredentialsValidation then we don't need to do anything in
	// preConfigureCallback as this is an explicit operation
	if skipCredentialsValidation {
		return nil
	}

	config := &awsbase.Config{
		AccessKey: stringValue(vars, "accessKey", []string{"AWS_ACCESS_KEY_ID"}),
		SecretKey: stringValue(vars, "secretKey", []string{"AWS_SECRET_ACCESS_KEY"}),
		Profile:   stringValue(vars, "profile", []string{"AWS_PROFILE"}),
		Token:     stringValue(vars, "token", []string{"AWS_SESSION_TOKEN"}),
		Region:    stringValue(vars, "region", []string{"AWS_REGION", "AWS_DEFAULT_REGION"}),
	}

	if details, ok := vars["assumeRole"]; ok {
		assumeRoleDetails := resource.NewPropertyMap(details)
		assumeRole := awsbase.AssumeRole{
			RoleARN:     stringValue(assumeRoleDetails, "roleArn", []string{}),
			ExternalID:  stringValue(assumeRoleDetails, "externalId", []string{}),
			Policy:      stringValue(assumeRoleDetails, "policy", []string{}),
			SessionName: stringValue(assumeRoleDetails, "sessionName", []string{}),
		}
		config.AssumeRole = &assumeRole
	}

	// By default `skipMetadataApiCheck` is true for Pulumi to speed operations
	// if we want to authenticate against the AWS API Metadata Service then the user
	// will specify that skipMetadataApiCheck: false
	// therefore, if we have skipMetadataApiCheck false, then we are enabling the imds client
	config.EC2MetadataServiceEnableState = imds.ClientDisabled
	if val, ok := vars["skipMetadataApiCheck"]; ok {
		if val.IsBool() && !val.BoolValue() {
			config.EC2MetadataServiceEnableState = imds.ClientEnabled
		}
	}

	// lastly let's set the sharedCreds and sharedConfig file. If these are not found then let's default to the
	// locations that AWS cli will store these values.
	var sharedCredentialsFilePaths []string
	sharedCredentialsFile := stringValue(vars, "sharedCredentialsFile", []string{"AWS_SHARED_CREDENTIALS_FILE"})
	if sharedCredentialsFile != "" {
		sharedCredentialsFilePaths = append(sharedCredentialsFilePaths, sharedCredentialsFile)
	}

	sharedCredentialsFiles := arrayValue(vars, "sharedCredentialsFiles",
		[]string{"AWS_SHARED_CREDENTIALS_FILE", "AWS_SHARED_CREDENTIALS_FILES"})
	if len(sharedCredentialsFiles) > 0 {
		sharedCredentialsFilePaths = append(sharedCredentialsFilePaths, sharedCredentialsFiles...)
	}

	if len(sharedCredentialsFilePaths) == 0 {
		sharedCredentialsFile := "~/.aws/credentials"
		credsPath, err := homedir.Expand(sharedCredentialsFile)
		if err != nil {
			return err
		}

		sharedCredentialsFilePaths = append(sharedCredentialsFilePaths, credsPath)
	}
	config.SharedCredentialsFiles = sharedCredentialsFilePaths

	sharedConfigFile := stringValue(vars, "sharedConfigFile", []string{"AWS_CONFIG_FILE"})
	if sharedConfigFile == "" {
		sharedConfigFile = "~/.aws/config"
	}
	configPath, err := homedir.Expand(sharedConfigFile)
	if err != nil {
		return err
	}

	config.SharedConfigFiles = []string{configPath}

	// if _, err := awsbase.GetAwsConfig(context.Background(), config); err != nil {

	// 	return fmt.Errorf("unable to validate AWS credentials. Make sure you have: \n\n" +
	// 		" \t • Set your AWS region, e.g. `pulumi config set aws:region us-west-2` \n" +
	// 		" \t • Configured your AWS credentials as per https://pulumi.io/install/aws.html \n" +
	// 		" \t You can also set these via cli using `aws configure`. \n\n")
	// }

	return nil
}

// managedByPulumi is a default used for some managed resources, in the absence of something more meaningful.
// var managedByPulumi = &tfbridge.DefaultInfo{Value: "Managed by Pulumi"}

// Provider returns additional overlaid schema and metadata associated with the aws package.
func Provider() tfbridge.ProviderInfo {
	p := shimv2.NewProvider(awsShim.NewProvider())

	prov := tfbridge.ProviderInfo{
		P:           p,
		Name:        "aws",
		Description: "A Pulumi package for creating and managing Amazon Web Services (AWS) cloud resources.",
		Keywords:    []string{"pulumi", "aws"},
		License:     "Apache-2.0",
		Homepage:    "https://pulumi.io",
		Repository:  "https://github.com/phillipedwards/pulumi-aws",
		Version:     "0.0.2",
		GitHubOrg:   "hashicorp",
		Config: map[string]*tfbridge.SchemaInfo{
			"region": {
				Type: awsTypeDefaultFile(awsMod, "Region"),
				Default: &tfbridge.DefaultInfo{
					EnvVars: []string{"AWS_REGION", "AWS_DEFAULT_REGION"},
				},
			},
			"skip_get_ec2_platforms": {
				Default: &tfbridge.DefaultInfo{
					Value: true,
				},
			},
			"skip_region_validation": {
				Default: &tfbridge.DefaultInfo{
					Value: true,
				},
			},
			"skip_credentials_validation": {
				Default: &tfbridge.DefaultInfo{
					// This is required to now be false! When this is true, we defer
					// the AWS credentials validation check to happen at resource
					// creation time. Although it may be a little slower validating
					// this upfront, we genuinely need to do this to ensure a good
					// user experience. If we don't validate upfront, then we can
					// be in a situation where a user can be waiting for a resource
					// creation timeout (default up to 30mins) to find out that they
					// have not got valid credentials
					Value: false,
				},
			},
			"skip_metadata_api_check": {
				Type: "boolean",
				Default: &tfbridge.DefaultInfo{
					Value: true,
				},
			},
		},
		PreConfigureCallback: preConfigureCallback,
		Resources: map[string]*tfbridge.ResourceInfo{

			// Identity and Access Management (IAM)
			"aws_iam_access_key": {Tok: awsResource(iamMod, "AccessKey")},
			"aws_iam_account_alias": {
				Tok: awsResource(iamMod, "AccountAlias"),
				Fields: map[string]*tfbridge.SchemaInfo{
					"account_alias": {
						CSharpName: "Alias",
					},
				},
			},
			"aws_iam_account_password_policy": {Tok: awsResource(iamMod, "AccountPasswordPolicy")},
			"aws_iam_group_policy": {
				Tok: awsResource(iamMod, "GroupPolicy"),
				Fields: map[string]*tfbridge.SchemaInfo{
					"policy": {
						Type:      "string",
						AltTypes:  []tokens.Type{awsType(iamMod, "documents", "PolicyDocument")},
						Transform: tfbridge.TransformJSONDocument,
					},
				},
			},
			"aws_iam_group":            {Tok: awsResource(iamMod, "Group")},
			"aws_iam_group_membership": {Tok: awsResource(iamMod, "GroupMembership")},
			"aws_iam_group_policy_attachment": {
				Tok: awsResource(iamMod, "GroupPolicyAttachment"),
				Fields: map[string]*tfbridge.SchemaInfo{
					"group": {
						Type:     "string",
						AltTypes: []tokens.Type{awsTypeDefaultFile(iamMod, "Group")},
					},
					"policy_arn": {
						Name: "policyArn",
						Type: awsTypeDefaultFile(awsMod, "ARN"),
					},
				},
				// We pass delete-before-replace: this is a leaf node and a create followed by a delete actually
				// deletes the same attachment we just created, since it is structurally equivalent!
				DeleteBeforeReplace: true,
			},
			"aws_iam_instance_profile": {
				Tok: awsResource(iamMod, "InstanceProfile"),
				Fields: map[string]*tfbridge.SchemaInfo{
					"role": {
						Type:     "string",
						AltTypes: []tokens.Type{awsTypeDefaultFile(iamMod, "Role")},
					},
				},
			},
			"aws_iam_openid_connect_provider": {Tok: awsResource(iamMod, "OpenIdConnectProvider")},
			"aws_iam_policy": {
				Tok: awsResource(iamMod, "Policy"),
				Fields: map[string]*tfbridge.SchemaInfo{
					"policy": {
						Type:       "string",
						AltTypes:   []tokens.Type{awsType(iamMod, "documents", "PolicyDocument")},
						Transform:  tfbridge.TransformJSONDocument,
						CSharpName: "PolicyDocument",
					},
				},
			},
			"aws_iam_policy_attachment": {
				Tok: awsResource(iamMod, "PolicyAttachment"),
				Fields: map[string]*tfbridge.SchemaInfo{
					"users": {
						Elem: &tfbridge.SchemaInfo{
							Type:     "string",
							AltTypes: []tokens.Type{awsTypeDefaultFile(iamMod, "User")},
						},
					},
					"roles": {
						Elem: &tfbridge.SchemaInfo{
							Type:     "string",
							AltTypes: []tokens.Type{awsTypeDefaultFile(iamMod, "Role")},
						},
					},
					"groups": {
						Elem: &tfbridge.SchemaInfo{
							Type:     "string",
							AltTypes: []tokens.Type{awsTypeDefaultFile(iamMod, "Group")},
						},
					},
					"policy_arn": {
						Name: "policyArn",
						Type: awsTypeDefaultFile(awsMod, "ARN"),
					},
				},
				// We pass delete-before-replace: this is a leaf node and a create followed by a delete actually
				// deletes the same attachment we just created, since it is structurally equivalent!
				DeleteBeforeReplace: true,
			},
			"aws_iam_role_policy_attachment": {
				Tok: awsResource(iamMod, "RolePolicyAttachment"),
				Fields: map[string]*tfbridge.SchemaInfo{
					"role": {
						Type:     "string",
						AltTypes: []tokens.Type{awsTypeDefaultFile(iamMod, "Role")},
					},
					"policy_arn": {
						Name: "policyArn",
						Type: awsTypeDefaultFile(awsMod, "ARN"),
					},
				},
				// We pass delete-before-replace: this is a leaf node and a create followed by a delete actually
				// deletes the same attachment we just created, since it is structurally equivalent!
				DeleteBeforeReplace: true,
			},
			"aws_iam_role_policy": {
				Tok: awsResource(iamMod, "RolePolicy"),
				Fields: map[string]*tfbridge.SchemaInfo{
					"role": {
						Type:     "string",
						AltTypes: []tokens.Type{awsTypeDefaultFile(iamMod, "Role")},
					},
					"policy": {
						Type:      "string",
						AltTypes:  []tokens.Type{awsType(iamMod, "documents", "PolicyDocument")},
						Transform: tfbridge.TransformJSONDocument,
					},
				},
			},
			"aws_iam_role": {
				Tok: awsResource(iamMod, "Role"),
				Fields: map[string]*tfbridge.SchemaInfo{
					"name": tfbridge.AutoName("name", 64, "-"),
					"assume_role_policy": {
						Type:      "string",
						AltTypes:  []tokens.Type{awsType(iamMod, "documents", "PolicyDocument")},
						Transform: tfbridge.TransformJSONDocument,
					},
				},
			},
			"aws_iam_saml_provider":         {Tok: awsResource(iamMod, "SamlProvider")},
			"aws_iam_server_certificate":    {Tok: awsResource(iamMod, "ServerCertificate")},
			"aws_iam_service_linked_role":   {Tok: awsResource(iamMod, "ServiceLinkedRole")},
			"aws_iam_user_group_membership": {Tok: awsResource(iamMod, "UserGroupMembership")},
			"aws_iam_user_policy_attachment": {
				Tok: awsResource(iamMod, "UserPolicyAttachment"),
				Fields: map[string]*tfbridge.SchemaInfo{
					"user": {
						Type:     "string",
						AltTypes: []tokens.Type{awsTypeDefaultFile(iamMod, "User")},
					},
					"policy_arn": {
						Name: "policyArn",
						Type: awsTypeDefaultFile(awsMod, "ARN"),
					},
				},
				// We pass delete-before-replace: this is a leaf node and a create followed by a delete actually
				// deletes the same attachment we just created, since it is structurally equivalent!
				DeleteBeforeReplace: true,
			},
			"aws_iam_user_policy": {
				Tok: awsResource(iamMod, "UserPolicy"),
				Fields: map[string]*tfbridge.SchemaInfo{
					"policy": {
						Type:      "string",
						AltTypes:  []tokens.Type{awsType(iamMod, "documents", "PolicyDocument")},
						Transform: tfbridge.TransformJSONDocument,
					},
				},
			},
			"aws_iam_user_ssh_key":                {Tok: awsResource(iamMod, "SshKey")},
			"aws_iam_user":                        {Tok: awsResource(iamMod, "User")},
			"aws_iam_user_login_profile":          {Tok: awsResource(iamMod, "UserLoginProfile")},
			"aws_iam_service_specific_credential": {Tok: awsResource(iamMod, "ServiceSpecificCredential")},
			"aws_iam_signing_certificate":         {Tok: awsResource(iamMod, "SigningCertificate")},
			"aws_iam_virtual_mfa_device":          {Tok: awsResource(iamMod, "VirtualMfaDevice")},
		},
		ExtraTypes: map[string]schema.ComplexTypeSpec{
			"aws:index/Region:Region": {
				ObjectTypeSpec: schema.ObjectTypeSpec{
					Type:        "string",
					Description: "A Region represents any valid Amazon region that may be targeted with deployments.",
				},
				Enum: []schema.EnumValueSpec{
					{Value: "af-south-1", Name: "AFSouth1"},
					{Value: "ap-east-1", Name: "APEast1"},
					{Value: "ap-northeast-1", Name: "APNortheast1"},
					{Value: "ap-northeast-2", Name: "APNortheast2"},
					{Value: "ap-northeast-3", Name: "APNortheast3"},
					{Value: "ap-south-1", Name: "APSouth1"},
					{Value: "ap-southeast-2", Name: "APSoutheast2"},
					{Value: "ap-southeast-1", Name: "APSoutheast1"},
					{Value: "ca-central-1", Name: "CACentral"},
					{Value: "cn-north-1", Name: "CNNorth1"},
					{Value: "cn-northwest-1", Name: "CNNorthwest1"},
					{Value: "eu-central-1", Name: "EUCentral1"},
					{Value: "eu-north-1", Name: "EUNorth1"},
					{Value: "eu-west-1", Name: "EUWest1"},
					{Value: "eu-west-2", Name: "EUWest2"},
					{Value: "eu-west-3", Name: "EUWest3"},
					{Value: "eu-south-1", Name: "EUSouth1"},
					{Value: "me-south-1", Name: "MESouth1"},
					{Value: "sa-east-1", Name: "SAEast1"},
					{Value: "us-gov-east-1", Name: "USGovEast1"},
					{Value: "us-gov-west-1", Name: "USGovWest1"},
					{Value: "us-east-1", Name: "USEast1"},
					{Value: "us-east-2", Name: "USEast2"},
					{Value: "us-west-1", Name: "USWest1"},
					{Value: "us-west-2", Name: "USWest2"},
				},
			},
		},
		DataSources: map[string]*tfbridge.DataSourceInfo{
			// AWS
			"aws_arn":                     {Tok: awsDataSource(awsMod, "getArn")},
			"aws_availability_zone":       {Tok: awsDataSource(awsMod, "getAvailabilityZone")},
			"aws_availability_zones":      {Tok: awsDataSource(awsMod, "getAvailabilityZones")},
			"aws_billing_service_account": {Tok: awsDataSource(awsMod, "getBillingServiceAccount")},
			"aws_caller_identity":         {Tok: awsDataSource(awsMod, "getCallerIdentity")},
			"aws_ip_ranges":               {Tok: awsDataSource(awsMod, "getIpRanges")},
			"aws_partition":               {Tok: awsDataSource(awsMod, "getPartition")},
			"aws_region":                  {Tok: awsDataSource(awsMod, "getRegion")},
			"aws_regions":                 {Tok: awsDataSource(awsMod, "getRegions")},
			"aws_default_tags":            {Tok: awsDataSource(awsMod, "getDefaultTags")},
			"aws_service":                 {Tok: awsDataSource(awsMod, "getService")},

			// IAM
			"aws_iam_account_alias":           {Tok: awsDataSource(iamMod, "getAccountAlias")},
			"aws_iam_group":                   {Tok: awsDataSource(iamMod, "getGroup")},
			"aws_iam_instance_profile":        {Tok: awsDataSource(iamMod, "getInstanceProfile")},
			"aws_iam_policy":                  {Tok: awsDataSource(iamMod, "getPolicy")},
			"aws_iam_policy_document":         {Tok: awsExperimentalDataSource(iamMod, "getPolicyDocument")},
			"aws_iam_role":                    {Tok: awsDataSource(iamMod, "getRole")},
			"aws_iam_server_certificate":      {Tok: awsDataSource(iamMod, "getServerCertificate")},
			"aws_iam_user":                    {Tok: awsDataSource(iamMod, "getUser")},
			"aws_iam_users":                   {Tok: awsDataSource(iamMod, "getUsers")},
			"aws_iam_session_context":         {Tok: awsDataSource(iamMod, "getSessionContext")},
			"aws_iam_roles":                   {Tok: awsDataSource(iamMod, "getRoles")},
			"aws_iam_user_ssh_key":            {Tok: awsDataSource(iamMod, "getUserSshKey")},
			"aws_iam_openid_connect_provider": {Tok: awsDataSource(iamMod, "getOpenidConnectProvider")},
			"aws_iam_saml_provider":           {Tok: awsDataSource(iamMod, "getSamlProvider")},
			"aws_iam_instance_profiles":       {Tok: awsDataSource(iamMod, "getInstanceProfiles")},
		},
		JavaScript: &tfbridge.JavaScriptInfo{
			Dependencies: map[string]string{
				"@pulumi/pulumi":    "^3.0.0",
				"aws-sdk":           "^2.0.0",
				"mime":              "^2.0.0",
				"builtin-modules":   "3.0.0",
				"read-package-tree": "^5.2.1",
				"resolve":           "^1.7.1",
			},
			DevDependencies: map[string]string{
				"@types/node": "^10.0.0", // so we can access strongly typed node definitions.
				"@types/mime": "^2.0.0",
			},
			Overlay: &tfbridge.OverlayInfo{
				DestFiles: []string{
					"arn.ts",    // ARN typedef
					"region.ts", // Region constants
					"tags.ts",   // Tags typedef (currently unused but left for compatibility)
					"utils.ts",  // Helpers,
					"awsMixins.ts",
				},
				Modules: map[string]*tfbridge.OverlayInfo{
					"iam": {
						DestFiles: []string{
							"documents.ts",       // policy document schemas.
							"managedPolicies.ts", // Deprecated ManagedPolicy constants.
							"principals.ts",      // Pre-defined objects representing Service Principals
						},
					},
				},
			},
		},
		Python: &tfbridge.PythonInfo{
			Requires: map[string]string{
				"pulumi": ">=3.0.0,<4.0.0",
			},
		},
		Golang: &tfbridge.GolangInfo{
			ImportBasePath: filepath.Join(
				fmt.Sprintf("github.com/pulumi/pulumi-%[1]s/sdk/", awsPkg),
				tfbridge.GetModuleMajorVersion("0.0.1"),
				"go",
				awsPkg,
			),
			GenerateResourceContainerTypes: true,
		},
		CSharp: &tfbridge.CSharpInfo{
			PackageReferences: map[string]string{
				"Pulumi": "3.*",
			},
			Namespaces: namespaceMap,
		},
	}

	prov.SetAutonaming(255, "-")

	return prov
}
