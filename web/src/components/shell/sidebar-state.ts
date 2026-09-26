/** Where the sidebar's expanded or collapsed state is kept between visits. */
export const sidebarStorageKey = "supermcp.sidebar";

/**
 * Whether the sidebar was left expanded. It starts expanded for somebody
 * who has never collapsed it, and when storage cannot be read (a private
 * window that refuses it, a policy that blocks it).
 */
export function readSidebarOpen(): boolean {
  try {
    return window.localStorage.getItem(sidebarStorageKey) !== "collapsed";
  } catch {
    return true;
  }
}

/** Remembers the choice; a refusal to store it only costs the memory. */
export function storeSidebarOpen(open: boolean): void {
  try {
    window.localStorage.setItem(sidebarStorageKey, open ? "expanded" : "collapsed");
  } catch {
    // Nothing to do: the sidebar still works, it just forgets.
  }
}
