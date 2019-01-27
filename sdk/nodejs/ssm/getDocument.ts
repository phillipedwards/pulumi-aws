// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * Gets the contents of the specified Systems Manager document.
 * 
 */
export function getDocument(args: GetDocumentArgs, opts?: pulumi.InvokeOptions): Promise<GetDocumentResult> {
    return pulumi.runtime.invoke("aws:ssm/getDocument:getDocument", {
        "documentFormat": args.documentFormat,
        "documentVersion": args.documentVersion,
        "name": args.name,
    }, opts);
}

/**
 * A collection of arguments for invoking getDocument.
 */
export interface GetDocumentArgs {
    /**
     * Returns the document in the specified format. The document format can be either JSON or YAML. JSON is the default format.
     */
    readonly documentFormat?: string;
    /**
     * The document version for which you want information.
     */
    readonly documentVersion?: string;
    /**
     * The name of the Systems Manager document.
     */
    readonly name: string;
}

/**
 * A collection of values returned by getDocument.
 */
export interface GetDocumentResult {
    /**
     * The ARN of the document.
     */
    readonly arn: string;
    /**
     * The contents of the document.
     */
    readonly content: string;
    /**
     * The type of the document.
     */
    readonly documentType: string;
    /**
     * id is the provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
}