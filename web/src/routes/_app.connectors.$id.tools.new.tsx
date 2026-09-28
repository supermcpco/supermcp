import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Text } from "@cloudflare/kumo";
import { ArrowLeft } from "@phosphor-icons/react";
import { connectorsGetOptions } from "../api/@tanstack/react-query.gen";
import { useSession } from "../lib/session";
import { Loading, NotFound } from "../lib/ui";
import { message, status } from "../lib/errors";
import { ToolEditor } from "../components/tool-editor";
import { transportOf } from "../lib/tool-api";
import { About, HeadingWithAbout } from "../components/about";

export const Route = createFileRoute("/_app/connectors/$id/tools/new")({
  component: NewTool,
});

function NewTool() {
  const { id } = Route.useParams();
  const { signedIn, can } = useSession();
  const navigate = useNavigate();
  const connector = useQuery({ ...connectorsGetOptions({ path: { id } }), enabled: signedIn, retry: false });

  if (status(connector.error) === 404) {
    return (
      <NotFound heading="Connector not found" back={{ to: "/connectors" }} backLabel="Back to connectors">
        This workspace has no connector at this address; it may have been deleted.
      </NotFound>
    );
  }

  return (
    <div className="grid gap-6">
      <Link to="/connectors/$id/tools" params={{ id }} className="flex items-center gap-1 text-kumo-subtle">
        <span className="h-lh flex items-center">
          <ArrowLeft size={14} aria-hidden />
        </span>
        <Text as="span">Tools{connector.data ? ` of ${connector.data.name}` : ""}</Text>
      </Link>

      <div className="grid gap-1.5">
        <HeadingWithAbout
          heading={
            <Text as="h1" variant="heading" size="lg">
              New tool
            </Text>
          }
          about={
            <About label="About new tools">
              <p>A tool uses the connector&rsquo;s address and sign-in, so it never needs credentials of its own.</p>
              <p>
                The request it would make is shown beside it as you type, with secrets redacted. Nothing is sent
                upstream until a model calls the saved tool.
              </p>
            </About>
          }
        />
        <Text>One thing a model can ask this connector to do.</Text>
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
