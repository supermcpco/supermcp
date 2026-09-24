import { useState } from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Text, Textarea } from "@cloudflare/kumo";
import { ArrowLeft } from "@phosphor-icons/react";
import type { ToolIssueDto } from "../api";
import { toolsGetOptions } from "../api/@tanstack/react-query.gen";
import { useSession } from "../lib/session";
import { Badge, Loading, SignInFirst } from "../lib/ui";
import { message } from "../lib/errors";
import { ToolEditor } from "../components/tool-editor";

export const Route = createFileRoute("/connectors/$id/tools/$toolId/")({
  component: EditTool,
});

const sourceLabel = { catalog: "from the catalog", import: "imported", custom: "custom" } as const;

function EditTool() {
  const { id, toolId } = Route.useParams();
  const { signedIn, can, loading } = useSession();
  const navigate = useNavigate();
  const tool = useQuery({ ...toolsGetOptions({ path: { id: toolId } }), enabled: signedIn, retry: false });
  const [warnings, setWarnings] = useState<ToolIssueDto[]>([]);
  const [savedAt, setSavedAt] = useState<number | null>(null);
  // Bumped to throw the draft away and start again from what is stored.
  const [generation, setGeneration] = useState(0);

  if (loading) return <Loading />;
  if (!signedIn) return <SignInFirst />;

  const t = tool.data;
  const canEdit = can("tools:update");

  return (
    <div className="grid gap-6">
      <Link to="/connectors/$id/tools" params={{ id }} className="flex items-center gap-1 text-kumo-subtle">
        <span className="h-lh flex items-center">
          <ArrowLeft size={14} aria-hidden />
        </span>
        <Text as="span">Tools</Text>
      </Link>

      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="grid gap-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <Text as="h1" variant="heading2">
              {t ? t.name : "Tool"}
            </Text>
            {t && <Badge>{sourceLabel[t.source]}</Badge>}
            {t?.edited && <Badge>edited</Badge>}
            {t && !t.enabled && <Badge>off</Badge>}
          </div>
          {t?.editedAt && (
            <Text variant="secondary">
              Last changed by hand {new Date(t.editedAt).toLocaleString()}
              {t.editedByName || t.editedBy ? ` by ${t.editedByName || t.editedBy}` : ""}.
            </Text>
          )}
        </div>
        <Link
          to="/connectors/$id/tools/$toolId/history"
          params={{ id, toolId }}
          className="rounded-md px-3 py-1.5 ring ring-kumo-line hover:bg-kumo-tint"
        >
          <Text as="span">History</Text>
        </Link>
      </div>

      {t?.source === "catalog" && (
        <Text>
          This tool came from the catalog. Once you change it, a later catalog update leaves your version alone rather
          than overwriting it.
        </Text>
      )}

      {savedAt !== null && (
        <div role="status" className="grid gap-1 rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
          <Text>Saved. Clients see the new version straight away.</Text>
          {warnings.length > 0 && (
            <ul className="grid gap-0.5">
              {warnings.map((w, n) => (
                <li key={`${w.rule}-${n}`}>
                  <Text as="span" variant="secondary">
                    Warning{w.field ? ` (${w.field})` : ""}: {w.message}
                  </Text>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {tool.isPending ? (
        <Loading />
      ) : tool.error ? (
        <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
          <Text>{message(tool.error)}</Text>
        </div>
      ) : !canEdit ? (
        <div className="grid gap-2">
          <Text>You can see this tool but not change it.</Text>
          <label className="grid gap-1.5">
            <Text as="span">Definition (JSON)</Text>
            <Textarea readOnly rows={24} className="font-mono text-[0.85em]" value={t?.definition ?? ""} />
          </label>
        </div>
      ) : (
        t && (
          <ToolEditor
            // A saved or reloaded tool is a fresh start: the draft is what
            // the server now holds, and so is the version it is checked against.
            key={`${t.version}-${generation}`}
            connectorId={id}
            transport={t.transport}
            tool={t}
            onSaved={async (result) => {
              setWarnings(result.warnings ?? []);
              setSavedAt(Date.now());
              await tool.refetch();
            }}
            onCancel={() => navigate({ to: "/connectors/$id/tools", params: { id } })}
            onReload={async () => {
              setSavedAt(null);
              await tool.refetch();
              setGeneration((g) => g + 1);
            }}
          />
        )
      )}
    </div>
  );
}
