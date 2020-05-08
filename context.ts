import express from "express";
import {ExecutionParams} from "subscriptions-transport-ws";
import FusionAuthClient from "@fusionauth/typescript-client";

export interface Context {
    req: express.Request;
    res: express.Response;
    connection?: ExecutionParams;
    fusionClientAuth: FusionAuthClient;
}
