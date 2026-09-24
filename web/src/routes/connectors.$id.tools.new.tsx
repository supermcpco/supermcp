import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Text } from "@cloudflare/kumo";
import { ArrowLeft } from "@phosphor-icons/react";
import { connectorsGetOptions } from "../api/@tanstack/react-query.gen";
import { useSession } from "../lib/session";
import { Loading, SignInFirst } from "../lib/ui";
import { message } from "../lib/errors";
import { ToolEditor } from "../components/tool-editor";
import { transportOf } from "../lib/tool-api";

export const Route = createFileRoute("/connectors/$id/tools/new")({
  component: NewTool,
});

function NewTool() {
  const { id } = Route.useParams();
  const { signedIn, can, loading } = useSession();
  const navigate = useNavigate();
  const connector = useQuery({ ...connectorsGetOptions({ path: { id } }), enabled: signedIn, retry: false });

  if (loading) return <Loading />;
  if (!signedIn) return <SignInFirst />;

  return (
    <div className="grid gap-6">
      <Link to="/connectors/$id/tools" params={{ id }} className="flex items-center gap-1 text-kumo-subtle">
        <span className="h-lh flex items-center">
          <ArrowLeft size={14} aria-hidden />
        </span>
        <Text as="span">Tools{connector.data ? ` of ${connector.data.name}` : ""}</Text>
      </Link>

      <div className="grid gap-1.5">
        <Text as="h1" variant="heading2">
          New tool
        </Text>
        <Text>
          A tool is one thing a model can ask this connector to do. It uses the connector's address and sign-in, so a
          new tool never needs credentials of its own. The request it would make is shown beside it as you type, with
          secrets redacted, and nothing is sent upstream until a model calls the saved tool.
        </Text>
      </div>

      {!can("tools:update") ? (
        <Text>You do not have permission to add tools to this connector.</Text>
      ) : connector.isPending ? (
        <Loading />
      ) : connector.error ? (
        <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
          <Text>{message(connector.error)}</Text>
        </div>
      ) : (
        <ToolEditor
          connectorId={id}
          transport={transportOf(connector.data.transport)}
          onSaved={async (result) => {
            await navigate({ to: "/connectors/$id/tools/$toolId", params: { id, toolId: result.tool.id } });
          }}
          onCancel={() => navigate({ to: "/connectors/$id/tools", params: { id } })}
        />
      )}
    </div>
  );
}
