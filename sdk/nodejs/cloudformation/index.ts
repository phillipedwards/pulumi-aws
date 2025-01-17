// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export { CloudFormationTypeArgs, CloudFormationTypeState } from "./cloudFormationType";
export type CloudFormationType = import("./cloudFormationType").CloudFormationType;
export const CloudFormationType: typeof import("./cloudFormationType").CloudFormationType = null as any;

export { GetCloudFormationTypeArgs, GetCloudFormationTypeResult, GetCloudFormationTypeOutputArgs } from "./getCloudFormationType";
export const getCloudFormationType: typeof import("./getCloudFormationType").getCloudFormationType = null as any;
export const getCloudFormationTypeOutput: typeof import("./getCloudFormationType").getCloudFormationTypeOutput = null as any;

export { GetExportArgs, GetExportResult, GetExportOutputArgs } from "./getExport";
export const getExport: typeof import("./getExport").getExport = null as any;
export const getExportOutput: typeof import("./getExport").getExportOutput = null as any;

export { GetStackArgs, GetStackResult, GetStackOutputArgs } from "./getStack";
export const getStack: typeof import("./getStack").getStack = null as any;
export const getStackOutput: typeof import("./getStack").getStackOutput = null as any;

export { StackArgs, StackState } from "./stack";
export type Stack = import("./stack").Stack;
export const Stack: typeof import("./stack").Stack = null as any;

export { StackSetArgs, StackSetState } from "./stackSet";
export type StackSet = import("./stackSet").StackSet;
export const StackSet: typeof import("./stackSet").StackSet = null as any;

export { StackSetInstanceArgs, StackSetInstanceState } from "./stackSetInstance";
export type StackSetInstance = import("./stackSetInstance").StackSetInstance;
export const StackSetInstance: typeof import("./stackSetInstance").StackSetInstance = null as any;

utilities.lazyLoad(exports, ["CloudFormationType"], () => require("./cloudFormationType"));
utilities.lazyLoad(exports, ["getCloudFormationType","getCloudFormationTypeOutput"], () => require("./getCloudFormationType"));
utilities.lazyLoad(exports, ["getExport","getExportOutput"], () => require("./getExport"));
utilities.lazyLoad(exports, ["getStack","getStackOutput"], () => require("./getStack"));
utilities.lazyLoad(exports, ["Stack"], () => require("./stack"));
utilities.lazyLoad(exports, ["StackSet"], () => require("./stackSet"));
utilities.lazyLoad(exports, ["StackSetInstance"], () => require("./stackSetInstance"));

const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "aws:cloudformation/cloudFormationType:CloudFormationType":
                return new CloudFormationType(name, <any>undefined, { urn })
            case "aws:cloudformation/stack:Stack":
                return new Stack(name, <any>undefined, { urn })
            case "aws:cloudformation/stackSet:StackSet":
                return new StackSet(name, <any>undefined, { urn })
            case "aws:cloudformation/stackSetInstance:StackSetInstance":
                return new StackSetInstance(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("aws", "cloudformation/cloudFormationType", _module)
pulumi.runtime.registerResourceModule("aws", "cloudformation/stack", _module)
pulumi.runtime.registerResourceModule("aws", "cloudformation/stackSet", _module)
pulumi.runtime.registerResourceModule("aws", "cloudformation/stackSetInstance", _module)
