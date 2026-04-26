import { isAuthRequired, verifyAuth } from "../../../shared/utils/apiAuth";
import type { AuthOutcome, PolicyContext, RoutePolicy } from "../context";
import { allow, reject } from "../context";

export const managementPolicy: RoutePolicy = {
  routeClass: "MANAGEMENT",
  async evaluate(ctx: PolicyContext): Promise<AuthOutcome> {
    if (!(await isAuthRequired())) {
      return allow({ kind: "anonymous", id: "anonymous", label: "auth-disabled" });
    }

    const error = await verifyAuth(ctx.request);
    if (error === null) {
      return allow({ kind: "dashboard_session", id: "dashboard" });
    }

    const status = error === "Invalid management token" ? 403 : 401;
    return reject(status, "AUTH_001", error);
  },
};
