import { NextResponse, type NextRequest } from "next/server";
import { generateRequestId } from "../../shared/utils/requestId";
import { classifyRoute } from "./classify";
import { clientApiPolicy } from "./policies/clientApi";
import { managementPolicy } from "./policies/management";
import { publicPolicy } from "./policies/public";
import {
  AUTHZ_HEADER_AUTH_ID,
  AUTHZ_HEADER_AUTH_KIND,
  AUTHZ_HEADER_AUTH_LABEL,
  AUTHZ_HEADER_AUTH_SCOPES,
  AUTHZ_HEADER_REQUEST_ID,
  AUTHZ_HEADER_ROUTE_CLASS,
  AUTHZ_TRUSTED_HEADERS,
} from "./headers";
import type { AuthSubject, RouteClass, RouteClassification } from "./types";
import type { AuthOutcome, RoutePolicy } from "./context";

export interface AuthzPipelineOptions {
  enforce?: boolean;
}

const POLICIES: Record<RouteClass, RoutePolicy> = {
  PUBLIC: publicPolicy,
  CLIENT_API: clientApiPolicy,
  MANAGEMENT: managementPolicy,
};

function stampSubject(headers: Headers, subject: AuthSubject): void {
  headers.set(AUTHZ_HEADER_AUTH_KIND, subject.kind);
  headers.set(AUTHZ_HEADER_AUTH_ID, subject.id);
  if (subject.label) headers.set(AUTHZ_HEADER_AUTH_LABEL, subject.label);
  if (subject.scopes && subject.scopes.length > 0) {
    headers.set(AUTHZ_HEADER_AUTH_SCOPES, subject.scopes.join(","));
  }
}

function rejectionResponse(
  outcome: Extract<AuthOutcome, { allow: false }>,
  classification: RouteClassification,
  requestId: string
): NextResponse {
  const response = NextResponse.json(
    {
      error: {
        code: outcome.code,
        message: outcome.message,
        correlation_id: requestId,
      },
    },
    { status: outcome.status }
  );
  response.headers.set(AUTHZ_HEADER_REQUEST_ID, requestId);
  response.headers.set(AUTHZ_HEADER_ROUTE_CLASS, classification.routeClass);
  return response;
}

export async function runAuthzPipeline(
  request: NextRequest,
  options: AuthzPipelineOptions = {}
): Promise<NextResponse> {
  const { pathname } = request.nextUrl;
  const method = request.method;

  const requestId = generateRequestId();
  const requestHeaders = new Headers(request.headers);
  for (const trusted of AUTHZ_TRUSTED_HEADERS) {
    requestHeaders.delete(trusted);
  }

  const classification = classifyRoute(pathname, method);
  requestHeaders.set(AUTHZ_HEADER_ROUTE_CLASS, classification.routeClass);
  requestHeaders.set(AUTHZ_HEADER_REQUEST_ID, requestId);

  if (!options.enforce) {
    const response = NextResponse.next({ request: { headers: requestHeaders } });
    response.headers.set(AUTHZ_HEADER_REQUEST_ID, requestId);
    response.headers.set(AUTHZ_HEADER_ROUTE_CLASS, classification.routeClass);
    return response;
  }

  const policy = POLICIES[classification.routeClass];
  const outcome = await policy.evaluate({ request, classification, requestId });

  if (!outcome.allow) {
    return rejectionResponse(outcome, classification, requestId);
  }

  stampSubject(requestHeaders, outcome.subject);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set(AUTHZ_HEADER_REQUEST_ID, requestId);
  response.headers.set(AUTHZ_HEADER_ROUTE_CLASS, classification.routeClass);
  return response;
}
