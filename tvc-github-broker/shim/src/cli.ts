/**
 * SHIM CLI.
 *
 *   bun shim/src/cli.ts init [--state .shim] --audience http://127.0.0.1:44020
 *                            [--installation-id 12345] [--repos demo,demo-2]
 *                            [--permissions contents:read,metadata:read]
 *     With --repos and --permissions, the policy lists that one exact query.
 *     Without them, it only requires a query and the broker allowlist
 *     enforces the scope.
 *   bun shim/src/cli.ts jwks [--state .shim]      # print the public JWK Set to pin
 *   bun shim/src/cli.ts info [--state .shim]      # org, users, enclave signer key
 */
import { parseArgs } from "node:util";
import { initState, loadState } from "./state.ts";

const { positionals, values } = parseArgs({
  allowPositionals: true,
  options: {
    state: { type: "string", default: ".shim" },
    audience: { type: "string" },
    "installation-id": { type: "string" },
    repos: { type: "string" },
    permissions: { type: "string" },
  },
});
const dir = values.state!;
switch (positionals[0]) {
  case "init": {
    if (!values.audience) throw new Error("--audience is required (the broker's exact origin)");
    await initState({
      dir,
      audience: values.audience,
      installationId: values["installation-id"],
      repositories: values.repos?.split(","),
      permissions: values.permissions?.split(","),
    });
    const st = await loadState(dir);
    console.log(JSON.stringify({ stateDir: dir, organizationId: st.org.organizationId, mintKid: st.mintKid, enclaveSignerPublicKey: st.enclaveSignerPublicKey }, null, 2));
    break;
  }
  case "jwks":
    console.log(JSON.stringify((await loadState(dir)).jwks, null, 2));
    break;
  case "info": {
    const st = await loadState(dir);
    console.log(
      JSON.stringify(
        { organizationId: st.org.organizationId, users: st.org.users.map((u) => ({ userId: u.userId, userName: u.userName, isRoot: u.isRoot })), allowedAudiences: st.org.allowedAudiences, mintKid: st.mintKid, enclaveSignerPublicKey: st.enclaveSignerPublicKey },
        null,
        2,
      ),
    );
    break;
  }
  default:
    console.error("usage: cli.ts init|jwks|info [--state DIR]");
    process.exit(2);
}
