import { NextResponse, type NextRequest } from "next/server";
import { generateRequestId } from "../../shared/utils/requestId";
import { classifyRoute } from "./classify";
import {
  AUTHZ_HEADER_REQUEST_ID,
  AUTHZ_HEADER_ROUTE_CLASS,
  AUTHZ_TRUSTED_HEADERS,
} from "./headers";

export interface AuthzPipelineOptions {
  enforce?: boolean;
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

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set(AUTHZ_HEADER_REQUEST_ID, requestId);
  response.headers.set(AUTHZ_HEADER_ROUTE_CLASS, classification.routeClass);

  void options.enforce;
  return response;
}
