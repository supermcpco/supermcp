import { useEffect, useRef, useState } from "react";
import { Button, Text } from "@cloudflare/kumo";
import { consentConnected, consentOutcome } from "../lib/connector";
import { toast } from "./shell/toast";

/**
 * What a vendor's consent screen came back with, said once. An approval
 * is a toast; a refusal stays on the page until dismissed, because it
 * says what to do next and a toast would take that away after a few
 * seconds. Either way the parameter is taken off the address as soon as
 * it has been read (`onRead`), so a reload or a shared link does not say
 * it again.
 *
 * `result` is read when this mounts: the return is a page load of its
 * own, and the address it came on is gone a moment later.
 */
export function ConsentReturn({ result, onRead }: { result: string | null; onRead: () => void }) {
  const [shown] = useState(result);
  const [dismissed, setDismissed] = useState(false);
  // Development's strict mode runs an effect twice; one toast is enough.
  const said = useRef(false);

  useEffect(() => {
    if (shown === null || said.current) return;
    said.current = true;
    if (shown === "ok") toast(consentConnected);
    onRead();
  }, [shown, onRead]);

  if (shown === null || shown === "ok" || dismissed) return null;
  return (
    <div role="alert" className="flex flex-wrap items-center gap-3 rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
      <Text>{consentOutcome(shown)}</Text>
      <Button onClick={() => setDismissed(true)}>Dismiss</Button>
    </div>
  );
}
