import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Text } from "@cloudflare/kumo";
import { invocationsListOptions } from "../api/@tanstack/react-query.gen";
import { useSession } from "../lib/session";
import { Badge } from "../lib/ui";

export const Route = createFileRoute("/_app/tool-calls")({
  component: ToolCalls,
});

function ToolCalls() {
  const { signedIn } = useSession();
  const q = useQuery({ ...invocationsListOptions({ query: { limit: 100 } }), enabled: signedIn, retry: false, refetchInterval: 10_000 });

  return (
    <div className="grid gap-6">
      <div className="grid gap-1.5">
        <Text as="h1" variant="heading2">
          Tool calls
        </Text>
        <Text>Every call an AI client made through this workspace.</Text>
      </div>

      {q.data?.length === 0 && <Text variant="secondary">No calls yet.</Text>}

      <table className="w-full">
        <thead className="border-b border-kumo-line text-left">
          <tr>
            <th className="py-2"><Text as="span" variant="secondary">Tool</Text></th>
            <th className="py-2"><Text as="span" variant="secondary">Status</Text></th>
            <th className="py-2"><Text as="span" variant="secondary">Duration</Text></th>
            <th className="py-2"><Text as="span" variant="secondary">When</Text></th>
          </tr>
        </thead>
        <tbody>
          {q.data?.map((i) => (
            <tr key={i.id} className="border-b border-kumo-line">
              <td className="py-2 font-mono text-[0.9em]">{i.toolName}</td>
              <td className="py-2">{i.status === "success" ? <Text as="span">ok</Text> : <Badge>{i.status}</Badge>}</td>
              <td className="py-2"><Text as="span">{i.durationMs} ms</Text></td>
              <td className="py-2"><Text as="span" variant="secondary">{new Date(i.createdAt).toLocaleString()}</Text></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
