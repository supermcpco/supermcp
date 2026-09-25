import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { RouterProvider, createRouter } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { routeTree } from "./routeTree.gen";
import { client } from "./api/client.gen";
import { createReauthGate, reauthInterceptors } from "./lib/reauth";
import { ReauthDialog } from "./components/reauth-dialog";
import "./app.css";

// Same origin; the session cookie is HttpOnly and sent automatically.
client.setConfig({ baseUrl: "", credentials: "same-origin" });

// A sensitive action from a session that signed in too long ago is
// refused with reauth_required. The interceptors hold the refused request
// while the dialog asks the person to confirm, then send it once more.
const reauthGate = createReauthGate();
const reauth = reauthInterceptors(reauthGate, (request) => fetch(request));
client.interceptors.request.use(reauth.request);
client.interceptors.response.use(reauth.response);

const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 30_000, retry: 1, refetchOnWindowFocus: false } },
});

const router = createRouter({ routeTree, context: { queryClient }, defaultPreload: "intent" });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
      <ReauthDialog gate={reauthGate} />
    </QueryClientProvider>
  </StrictMode>,
);
